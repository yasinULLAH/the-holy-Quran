<?php
session_start();
date_default_timezone_set('Asia/Karachi'); // Adjust timezone as needed

// --- Configuration ---
define('DB_FILE', 'quran.db');
define('DATA_FILE', 'data/data.AM'); // Ensure this path is correct and readable
define('ITEMS_PER_PAGE', 20);
define('SEARCH_RESULTS_PER_PAGE', 10);
define('APP_NAME', 'Quran Explorer');

// User Roles
define('ROLE_PUBLIC', 'Public');
define('ROLE_USER', 'User');
define('ROLE_ADMIN', 'Admin');

// --- Database Setup ---
function getDb() {
    static $db = null;
    if ($db === null) {
        try {
            $db = new PDO('sqlite:' . DB_FILE);
            $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            die("Database connection failed: " . $e->getMessage());
        }
    }
    return $db;
}

function initializeDatabase() {
    $db = getDb();
    $db->exec("CREATE TABLE IF NOT EXISTS ayahs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        surah_number INTEGER NOT NULL,
        ayah_number INTEGER NOT NULL,
        global_ayah_number INTEGER NOT NULL UNIQUE,
        arabic_text TEXT NOT NULL,
        urdu_translation TEXT NOT NULL,
        UNIQUE(surah_number, ayah_number)
    )");

    $db->exec("CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT '" . ROLE_USER . "',
        last_reading_surah INTEGER DEFAULT 1,
        last_reading_ayah INTEGER DEFAULT 1
    )");

    $db->exec("CREATE TABLE IF NOT EXISTS bookmarks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        surah_number INTEGER NOT NULL,
        ayah_number INTEGER NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(user_id, surah_number, ayah_number)
    )");


    // Import data if ayahs table is empty and data file exists
    $stmt_check = $db->query("SELECT COUNT(*) as count FROM ayahs");
    $count = $stmt_check->fetchColumn();

    if ($count == 0) { // Only run import if table is empty
         if (file_exists(DATA_FILE)) {
             importData(DATA_FILE);
         } else {
              error_log("Data file not found during initialization: " . DATA_FILE);
              // Display error to user or handle appropriately
         }
         // Create indexes after initial import attempt
         error_log("Creating indexes after import check...");
         $db->exec("CREATE INDEX IF NOT EXISTS idx_ayahs_surah_ayah ON ayahs (surah_number, ayah_number)");
         $db->exec("CREATE INDEX IF NOT EXISTS idx_ayahs_global ON ayahs (global_ayah_number)");
         $db->exec("CREATE INDEX IF NOT EXISTS idx_ayahs_search_arabic ON ayahs (arabic_text)");
         $db->exec("CREATE INDEX IF NOT EXISTS idx_ayahs_search_urdu ON ayahs (urdu_translation)");
         $db->exec("CREATE INDEX IF NOT EXISTS idx_users_email ON users (email)");
         $db->exec("CREATE INDEX IF NOT EXISTS idx_bookmarks_user ON bookmarks (user_id)");
         error_log("Indexes created.");
    }


    // Ensure Admin user exists
    $stmt = $db->prepare("SELECT COUNT(*) FROM users WHERE email = ?");
    $stmt->execute(['admin@example.com']);
    if ($stmt->fetchColumn() == 0) {
        $db->prepare("INSERT INTO users (email, password, role) VALUES (?, ?, ?)")
           ->execute(['admin@example.com', password_hash('admin123', PASSWORD_DEFAULT), ROLE_ADMIN]);
    }
}

function importData($dataFile) {
    $db = getDb();
    // Check again within function just in case multiple requests hit simultaneously before file is created
    $stmt_check = $db->query("SELECT COUNT(*) as count FROM ayahs");
    if ($stmt_check->fetchColumn() > 0) {
        error_log("Ayahs table already populated. Skipping import function call.");
        return;
    }

    if (!file_exists($dataFile)) {
        error_log("Data file not found: " . $dataFile);
        die("Error: Data file ($dataFile) not found. Please ensure it's in the correct location.");
    }
     if (!is_readable($dataFile)) {
        error_log("Data file not readable: " . $dataFile);
        die("Error: Data file ($dataFile) is not readable by the web server. Check permissions.");
     }

    $handle = fopen($dataFile, "r");
    if ($handle) {
        error_log("Starting data import from: " . $dataFile);
        $db->beginTransaction();
        $stmt = $db->prepare("INSERT OR IGNORE INTO ayahs (surah_number, ayah_number, global_ayah_number, arabic_text, urdu_translation) VALUES (?, ?, ?, ?, ?)");
        $globalAyahCounter = 0;
        $lineCount = 0;
        $importedCount = 0;
        $skippedMalformed = 0;
        $skippedDuplicate = 0;

        while (($line = fgets($handle)) !== false) {
            $lineCount++;
            $line = trim($line);
            if (empty($line)) continue;

            if (preg_match('/^(.*?) ترجمہ: (.*?)<br\/>س\s+(\d+)\s+آ\s+(\d+)$/u', $line, $matches)) {
                $arabic_text = trim($matches[1]);
                $urdu_translation = trim($matches[2]);
                $surah_number = intval($matches[3]);
                $ayah_number = intval($matches[4]);

                if ($surah_number <= 0 || $ayah_number <= 0 || $surah_number > 114) {
                     error_log("Skipping invalid data at line $lineCount: Surah $surah_number, Ayah $ayah_number");
                     $skippedMalformed++;
                     continue;
                }

                $globalAyahCounter++;

                try {
                     $stmt->execute([$surah_number, $ayah_number, $globalAyahCounter, $arabic_text, $urdu_translation]);
                     if ($stmt->rowCount() > 0) {
                         $importedCount++;
                     } else {
                         $check_dup_stmt = $db->prepare("SELECT global_ayah_number FROM ayahs WHERE surah_number = ? AND ayah_number = ?");
                         $check_dup_stmt->execute([$surah_number, $ayah_number]);
                         $existing_global_num = $check_dup_stmt->fetchColumn();

                         if($existing_global_num !== false) {
                             error_log("Duplicate Ayah S{$surah_number}:A{$ayah_number} found at line $lineCount. Already exists as global number {$existing_global_num}. Skipping insert.");
                             $skippedDuplicate++;
                             // Correct global counter: It should reflect the *next* number to be inserted for a *new* unique Ayah.
                             // Since this one was a duplicate, the intended global number ($globalAyahCounter) wasn't used.
                             // We decrement it so the next *valid* Ayah gets the correct $globalAyahCounter value.
                             $globalAyahCounter--;
                         } else {
                             error_log("Database insert failed (not duplicate, rowCount 0) at line $lineCount: S{$surah_number}:A{$ayah_number}");
                             $skippedMalformed++;
                              $globalAyahCounter--;
                         }
                     }
                } catch (PDOException $e) {
                     error_log("Database exception at line $lineCount: " . $e->getMessage() . " - Data: S{$surah_number}:A{$ayah_number}");
                     $skippedMalformed++;
                     $globalAyahCounter--;
                }

            } else {
                 error_log("Skipping malformed line $lineCount (Regex mismatch): " . $line);
                 $skippedMalformed++;
            }
        }
        fclose($handle);

        try {
            $db->commit();
            error_log("Data import finished. Total lines processed: $lineCount. Imported: $importedCount. Skipped (Malformed/Error): $skippedMalformed. Skipped (Duplicates): $skippedDuplicate. Final Global Ayah Counter value: " . $globalAyahCounter);
             // Verify count after import
            $final_count = $db->query("SELECT COUNT(*) FROM ayahs")->fetchColumn();
            $max_global = $db->query("SELECT MAX(global_ayah_number) FROM ayahs")->fetchColumn();
             error_log("Verification: DB row count = $final_count, Max global_ayah_number = $max_global");
        } catch (PDOException $e) {
            error_log("Commit failed: " . $e->getMessage());
            $db->rollBack();
            die("Database commit failed during import. Check error logs.");
        }
    } else {
        error_log("Error opening data file for reading: " . $dataFile);
         die("Failed to open data file ($dataFile).");
    }
}


// --- Security Functions ---
function generateCsrfToken() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verifyCsrfToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

function sanitize($data) {
    if (is_array($data)) {
        return array_map('sanitize', $data);
    }
    // Preserve Arabic characters, encode HTML special chars
    return htmlspecialchars(trim((string)$data), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

// --- User Management Functions ---
function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

function getCurrentUserRole() {
    if (!isLoggedIn()) {
        return ROLE_PUBLIC;
    }
    $db = getDb();
    $stmt = $db->prepare("SELECT role FROM users WHERE id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $user = $stmt->fetch();
    return $user ? $user['role'] : ROLE_PUBLIC;
}

function getCurrentUser() {
     if (!isLoggedIn()) return null;
     $db = getDb();
     $stmt = $db->prepare("SELECT id, email, role, last_reading_surah, last_reading_ayah FROM users WHERE id = ?");
     $stmt->execute([$_SESSION['user_id']]);
     return $stmt->fetch();
}

function isAdmin() {
    return getCurrentUserRole() === ROLE_ADMIN;
}

function handleRegister($email, $password, $csrf_token) {
    if (!verifyCsrfToken($csrf_token)) return "Invalid CSRF token.";
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) return "Invalid email format.";
    if (strlen($password) < 6) return "Password must be at least 6 characters long.";

    $db = getDb();
    $stmt = $db->prepare("SELECT id FROM users WHERE email = ?");
    $stmt->execute([$email]);
    if ($stmt->fetch()) return "Email already registered.";

    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
    $stmt = $db->prepare("INSERT INTO users (email, password, role) VALUES (?, ?, ?)");
    if ($stmt->execute([$email, $hashedPassword, ROLE_USER])) {
        return true;
    } else {
        return "Registration failed. Please try again.";
    }
}

function handleLogin($email, $password, $csrf_token) {
    if (!verifyCsrfToken($csrf_token)) return "Invalid CSRF token.";

    $db = getDb();
    $stmt = $db->prepare("SELECT id, email, password, role, last_reading_surah, last_reading_ayah FROM users WHERE email = ?");
    $stmt->execute([$email]);
    $user = $stmt->fetch();

    if ($user && password_verify($password, $user['password'])) {
        session_regenerate_id(true);
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['user_email'] = $user['email'];
        $_SESSION['user_role'] = $user['role'];
        // Restore reading progress only if valid values exist
        $_SESSION['current_surah'] = ($user['last_reading_surah'] > 0) ? $user['last_reading_surah'] : 1;
        $_SESSION['current_ayah'] = ($user['last_reading_ayah'] > 0) ? $user['last_reading_ayah'] : 1;
        return true;
    } else {
        return "Invalid email or password.";
    }
}

function handleLogout() {
    // Save progress before logging out
    if(isLoggedIn()){
        saveUserProgress();
    }
    session_unset();
    session_destroy();
    header("Location: index.php");
    exit;
}

function saveUserProgress() {
    if (isLoggedIn() && isset($_SESSION['current_surah']) && isset($_SESSION['current_ayah'])) {
         // Basic validation before saving
         $surah_to_save = filter_var($_SESSION['current_surah'], FILTER_VALIDATE_INT, ["options" => ["min_range"=>1, "max_range"=>114]]);
         $ayah_to_save = filter_var($_SESSION['current_ayah'], FILTER_VALIDATE_INT, ["options" => ["min_range"=>1]]); // Max range varies

         if($surah_to_save !== false && $ayah_to_save !== false) {
            $db = getDb();
            $stmt = $db->prepare("UPDATE users SET last_reading_surah = ?, last_reading_ayah = ? WHERE id = ?");
            $stmt->execute([$surah_to_save, $ayah_to_save, $_SESSION['user_id']]);
         } else {
              error_log("Invalid session progress values for user ID {$_SESSION['user_id']}: Surah={$_SESSION['current_surah']}, Ayah={$_SESSION['current_ayah']}");
         }
    }
}

// --- Quran Data Functions ---
function getTotalAyahs() {
    static $total = null;
    if ($total === null) {
        try {
            $db = getDb();
            $stmt = $db->query("SELECT MAX(global_ayah_number) FROM ayahs");
            $result = $stmt->fetchColumn();
            // Use result only if it's a positive integer, otherwise fallback
            $total = ($result && $result > 0) ? (int)$result : 6236;
        } catch (PDOException $e) {
             error_log("Error fetching total ayahs: " . $e->getMessage());
             $total = 6236; // Fallback on error
        }
    }
    return $total;
}

function getAyahByGlobalNumber($global_number) {
     $db = getDb();
     $stmt = $db->prepare("SELECT * FROM ayahs WHERE global_ayah_number = ?");
     $stmt->execute([$global_number]);
     return $stmt->fetch();
}


function getAyahBySurahAyah($surah, $ayah) {
    $db = getDb();
    $stmt = $db->prepare("SELECT * FROM ayahs WHERE surah_number = ? AND ayah_number = ?");
    $stmt->execute([$surah, $ayah]);
    return $stmt->fetch();
}

function getAyahsPage($page) {
    $totalAyahs = getTotalAyahs();
    $totalPages = ceil($totalAyahs / ITEMS_PER_PAGE);
    $page = max(1, min($page, $totalPages)); // Clamp page number
    $offset = ($page - 1) * ITEMS_PER_PAGE;

    $db = getDb();
    // Fetch based on global ayah number for consistent paging
    try {
        $stmt = $db->prepare("SELECT * FROM ayahs ORDER BY global_ayah_number LIMIT :limit OFFSET :offset");
        $stmt->bindValue(':limit', ITEMS_PER_PAGE, PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->fetchAll();
    } catch (PDOException $e) {
        error_log("Error fetching ayahs page $page: " . $e->getMessage());
        return []; // Return empty array on error
    }
}

function getPageNumberForAyah($surah, $ayah) {
     // Validate input
     $surah = filter_var($surah, FILTER_VALIDATE_INT, ["options" => ["min_range"=>1, "max_range"=>114]]);
     $ayah = filter_var($ayah, FILTER_VALIDATE_INT, ["options" => ["min_range"=>1]]);

     if ($surah === false || $ayah === false) {
          return 1; // Return page 1 for invalid input
     }

     try {
         $db = getDb();
         $stmt = $db->prepare("SELECT global_ayah_number FROM ayahs WHERE surah_number = ? AND ayah_number = ?");
         $stmt->execute([$surah, $ayah]);
         $result = $stmt->fetch();
         if ($result && isset($result['global_ayah_number'])) {
             $globalAyahNumber = (int)$result['global_ayah_number'];
             return floor(($globalAyahNumber - 1) / ITEMS_PER_PAGE) + 1;
         }
     } catch (PDOException $e) {
         error_log("Error getting page number for S{$surah}:A{$ayah}: " . $e->getMessage());
     }
     return 1; // Default to page 1 if not found or error
}


function getRandomAyahs($count = 10) {
    try {
        $db = getDb();
        // Ensure count is a positive integer
        $limit = max(1, (int)$count);
        $stmt = $db->query("SELECT * FROM ayahs ORDER BY RANDOM() LIMIT " . $limit);
        return $stmt->fetchAll();
    } catch (PDOException $e) {
         error_log("Error fetching random ayahs: " . $e->getMessage());
        return [];
    }
}

function searchAyahs($query, $page = 1) {
    $db = getDb();
    $searchPage = max(1, (int)$page);
    $offset = ($searchPage - 1) * SEARCH_RESULTS_PER_PAGE;
    // Basic sanitization, though LIKE with PDO binding is generally safe for basic patterns
    $searchQuery = '%' . str_replace(['%', '_'], ['\%', '\_'], $query) . '%'; // Escape LIKE wildcards in query

    $results = [];
    $totalResults = 0;

    try {
        // Prepare query for counting total results
        $countStmt = $db->prepare("SELECT COUNT(*) FROM ayahs WHERE arabic_text LIKE :query OR urdu_translation LIKE :query");
        $countStmt->bindValue(':query', $searchQuery, PDO::PARAM_STR);
        $countStmt->execute();
        $totalResults = (int)$countStmt->fetchColumn();

        if ($totalResults > 0) {
            // Prepare query for fetching paginated results
            $stmt = $db->prepare("SELECT * FROM ayahs WHERE arabic_text LIKE :query OR urdu_translation LIKE :query ORDER BY global_ayah_number LIMIT :limit OFFSET :offset");
            $stmt->bindValue(':query', $searchQuery, PDO::PARAM_STR);
            $stmt->bindValue(':limit', SEARCH_RESULTS_PER_PAGE, PDO::PARAM_INT);
            $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
            $stmt->execute();
            $results = $stmt->fetchAll();
        }
    } catch (PDOException $e) {
        error_log("Error searching ayahs for query '{$query}': " . $e->getMessage());
        // Return empty results on error
        $results = [];
        $totalResults = 0;
    }

    return ['results' => $results, 'total' => $totalResults];
}

// --- Bookmark Functions ---
function addBookmark($user_id, $surah, $ayah) {
    $db = getDb();
    $stmt = $db->prepare("INSERT OR IGNORE INTO bookmarks (user_id, surah_number, ayah_number) VALUES (?, ?, ?)");
    return $stmt->execute([$user_id, $surah, $ayah]);
}

function removeBookmark($user_id, $surah, $ayah) {
    $db = getDb();
    $stmt = $db->prepare("DELETE FROM bookmarks WHERE user_id = ? AND surah_number = ? AND ayah_number = ?");
    return $stmt->execute([$user_id, $surah, $ayah]);
}

function getUserBookmarks($user_id) {
    $db = getDb();
    $stmt = $db->prepare("SELECT b.surah_number, b.ayah_number, a.arabic_text, a.urdu_translation
                          FROM bookmarks b
                          JOIN ayahs a ON b.surah_number = a.surah_number AND b.ayah_number = a.ayah_number
                          WHERE b.user_id = ? ORDER BY b.surah_number, b.ayah_number");
    $stmt->execute([$user_id]);
    return $stmt->fetchAll();
}

function isBookmarked($user_id, $surah, $ayah) {
     if (!isLoggedIn()) return false;
     $db = getDb();
     $stmt = $db->prepare("SELECT COUNT(*) FROM bookmarks WHERE user_id = ? AND surah_number = ? AND ayah_number = ?");
     $stmt->execute([$user_id, $surah, $ayah]);
     return $stmt->fetchColumn() > 0;
}


// --- Admin Functions ---
function getAllUsers() {
    if (!isAdmin()) return [];
    $db = getDb();
    $stmt = $db->query("SELECT id, email, role FROM users ORDER BY id");
    return $stmt->fetchAll();
}

function updateUserRole($user_id, $role) {
    if (!isAdmin()) return false;
    if (!in_array($role, [ROLE_USER, ROLE_ADMIN])) return false; // Validate role
    $db = getDb();
    $stmt = $db->prepare("UPDATE users SET role = ? WHERE id = ?");
    return $stmt->execute([$role, $user_id]);
}

function deleteUser($user_id) {
    if (!isAdmin()) return false;
    if ($user_id == $_SESSION['user_id']) return false; // Admin cannot delete self
    $db = getDb();
    // Consider deleting related bookmarks? Not strictly necessary with ON DELETE CASCADE
    $stmt = $db->prepare("DELETE FROM users WHERE id = ?");
    return $stmt->execute([$user_id]);
}

function getAnalytics() {
    if (!isAdmin()) return [];
    $db = getDb();
    $userCount = $db->query("SELECT COUNT(*) FROM users")->fetchColumn();
    $bookmarkCount = $db->query("SELECT COUNT(*) FROM bookmarks")->fetchColumn();
    $ayahCount = getTotalAyahs();
    return [
        'Total Users' => $userCount,
        'Total Bookmarks' => $bookmarkCount,
        'Total Ayahs' => $ayahCount
    ];
}

// --- Initialization and Routing ---
initializeDatabase();
$csrf_token = generateCsrfToken();

// Get parameters safely
$action = filter_input(INPUT_REQUEST, 'action', FILTER_SANITIZE_SPECIAL_CHARS) ?? 'read';
$page = filter_input(INPUT_GET, 'page', FILTER_VALIDATE_INT, ['options' => ['default' => 1, 'min_range' => 1]]);
$surah = filter_input(INPUT_REQUEST, 'surah', FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 114]]);
$ayah = filter_input(INPUT_REQUEST, 'ayah', FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
$searchQuery = trim(filter_input(INPUT_GET, 'q', FILTER_SANITIZE_SPECIAL_CHARS) ?? '');
$searchPage = filter_input(INPUT_GET, 'spage', FILTER_VALIDATE_INT, ['options' => ['default' => 1, 'min_range' => 1]]);

$errorMessage = '';
$successMessage = '';
$current_user = getCurrentUser(); // Fetch current user details if logged in

// Set initial/default reading position
if (!isset($_SESSION['current_surah']) || !isset($_SESSION['current_ayah'])) {
     if (isLoggedIn() && $current_user) {
         $_SESSION['current_surah'] = $current_user['last_reading_surah'] > 0 ? $current_user['last_reading_surah'] : 1;
         $_SESSION['current_ayah'] = $current_user['last_reading_ayah'] > 0 ? $current_user['last_reading_ayah'] : 1;
     } else {
         $_SESSION['current_surah'] = 1;
         $_SESSION['current_ayah'] = 1;
     }
}

// Handle specific surah/ayah request, overriding session/user defaults for current view
if ($surah !== null && $ayah !== null) {
     $_SESSION['current_surah'] = $surah;
     $_SESSION['current_ayah'] = $ayah;
     // Calculate the page for this specific ayah request
     $page = getPageNumberForAyah($surah, $ayah);
}


// Handle POST requests
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $postAction = filter_input(INPUT_POST, 'action', FILTER_SANITIZE_SPECIAL_CHARS);
    $postCsrf = filter_input(INPUT_POST, 'csrf_token', FILTER_SANITIZE_SPECIAL_CHARS);

    if (!verifyCsrfToken($postCsrf)) {
        $errorMessage = 'Invalid request. Please try again.';
    } else {
        switch ($postAction) {
            case 'register':
                $email = filter_input(INPUT_POST, 'email', FILTER_VALIDATE_EMAIL);
                $password = $_POST['password'] ?? ''; // Get raw password
                if ($email === false) $errorMessage = "Invalid email format.";
                elseif(empty($password)) $errorMessage = "Password cannot be empty.";
                else {
                     $result = handleRegister($email, $password, $postCsrf);
                     if ($result === true) {
                         $successMessage = "Registration successful! Please login.";
                         $action = 'login';
                     } else {
                         $errorMessage = $result;
                         $action = 'register';
                     }
                 }
                 if ($errorMessage) $action = 'register'; // Ensure register form shows on error
                break;
            case 'login':
                $email = filter_input(INPUT_POST, 'email', FILTER_VALIDATE_EMAIL);
                $password = $_POST['password'] ?? '';
                 if ($email === false) $errorMessage = "Invalid email format.";
                 elseif(empty($password)) $errorMessage = "Password cannot be empty.";
                 else {
                    $result = handleLogin($email, $password, $postCsrf);
                    if ($result === true) {
                        header("Location: index.php?action=read");
                        exit;
                    } else {
                        $errorMessage = $result;
                        $action = 'login';
                    }
                 }
                 if($errorMessage) $action = 'login'; // Ensure login form shows on error
                break;
            case 'bookmark':
                if (isLoggedIn()) {
                    $b_surah = filter_input(INPUT_POST, 'surah', FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 114]]);
                    $b_ayah = filter_input(INPUT_POST, 'ayah', FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
                    $current_page_for_redirect = filter_input(INPUT_POST, 'current_page', FILTER_VALIDATE_INT, ['options' => ['default'=>1, 'min_range'=>1]]);


                    if ($b_surah && $b_ayah) {
                         if (isset($_POST['add'])) {
                             addBookmark($_SESSION['user_id'], $b_surah, $b_ayah);
                         } elseif (isset($_POST['remove'])) {
                             removeBookmark($_SESSION['user_id'], $b_surah, $b_ayah);
                         }
                          // Redirect back to the current reading page, preserving scroll position via hash
                         header("Location: index.php?action=read&page=$current_page_for_redirect#ayah-$b_surah-$b_ayah");
                         exit;
                    } else {
                         $errorMessage = "Invalid data for bookmark.";
                         // Fall through to reload current action/page
                    }
                }
                break;
             case 'update_role':
                 if (isAdmin()) {
                     $user_id = filter_input(INPUT_POST, 'user_id', FILTER_VALIDATE_INT);
                     $new_role = filter_input(INPUT_POST, 'role', FILTER_SANITIZE_SPECIAL_CHARS);
                     if ($user_id && $new_role) {
                         if (updateUserRole($user_id, $new_role)) {
                             $successMessage = "User role updated.";
                         } else {
                             $errorMessage = "Failed to update role.";
                         }
                     } else {
                          $errorMessage = "Invalid user ID or role.";
                     }
                     $action = 'admin'; // Refresh admin page
                 }
                 break;
             case 'delete_user':
                  if (isAdmin()) {
                     $user_id = filter_input(INPUT_POST, 'user_id', FILTER_VALIDATE_INT);
                      if($user_id) {
                         if (deleteUser($user_id)) {
                             $successMessage = "User deleted.";
                         } else {
                             $errorMessage = "Failed to delete user (cannot delete self or error occurred).";
                         }
                     } else {
                          $errorMessage = "Invalid user ID.";
                     }
                     $action = 'admin'; // Refresh admin page
                 }
                 break;
        }
    }
} else { // Handle GET requests
    switch ($action) {
        case 'logout':
            handleLogout();
            break;
        case 'read':
            // If page is explicitly set in GET, use it
            if (isset($_GET['page'])) {
                 $page = filter_input(INPUT_GET, 'page', FILTER_VALIDATE_INT, ['options' => ['default' => 1, 'min_range' => 1]]);
                  // Update session surah/ayah based on the first ayah of the target page
                  $offset = ($page - 1) * ITEMS_PER_PAGE;
                  try {
                     $db = getDb();
                     $stmt = $db->prepare("SELECT surah_number, ayah_number FROM ayahs ORDER BY global_ayah_number LIMIT 1 OFFSET :offset");
                     $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
                     $stmt->execute();
                     $firstAyahOnPage = $stmt->fetch();
                     if ($firstAyahOnPage) {
                          $_SESSION['current_surah'] = $firstAyahOnPage['surah_number'];
                          $_SESSION['current_ayah'] = $firstAyahOnPage['ayah_number'];
                     }
                  } catch (PDOException $e) {
                     error_log("Error finding first ayah on page $page: " . $e->getMessage());
                  }

            } elseif (isset($_SESSION['current_surah']) && isset($_SESSION['current_ayah'])) {
                // Otherwise, calculate page from session/saved progress
                 $page = getPageNumberForAyah($_SESSION['current_surah'], $_SESSION['current_ayah']);
            } else {
                 // Fallback if session isn't set (should be handled by initial setup)
                 $page = 1;
                 $_SESSION['current_surah'] = 1;
                 $_SESSION['current_ayah'] = 1;
            }

            // Save progress for logged-in users whenever they access 'read'
            if (isLoggedIn()) {
                 saveUserProgress();
            }
            break;
        case 'set_read_point':
             $set_surah = filter_input(INPUT_GET, 'surah', FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 114]]);
             $set_ayah = filter_input(INPUT_GET, 'ayah', FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);

             if ($set_surah && $set_ayah) {
                 $_SESSION['current_surah'] = $set_surah;
                 $_SESSION['current_ayah'] = $set_ayah;
                  if (isLoggedIn()) {
                     saveUserProgress(); // Save immediately for logged-in users
                 }
                 $redirect_page = getPageNumberForAyah($set_surah, $set_ayah);
                 header("Location: index.php?action=read&page=$redirect_page#ayah-$set_surah-$set_ayah");
                 exit;
             } else {
                  // Invalid surah/ayah, redirect to default read page
                  header("Location: index.php?action=read");
                  exit;
             }
             break; // Unreachable, but good practice
        case 'bookmarks':
             if (!isLoggedIn()) {
                  header("Location: index.php?action=login&redirect=bookmarks"); // Redirect to login
                  exit;
             }
             break;
        case 'admin':
             if (!isAdmin()) {
                  header("Location: index.php?action=read"); // Redirect non-admins
                  exit;
             }
             break;
        case 'search':
             // Handled by main data fetching logic below based on $searchQuery
             break;
        case 'random':
             // This will just trigger fetching random ayahs below, view remains 'read' typically
              $action = 'read'; // Or set a specific view if needed
             break;
         // Default/Fallback: 'login', 'register', or 'read' if action is unknown
         default:
             if (!in_array($action, ['login', 'register'])) {
                 $action = 'read';
             }
             break;
    }
}

// Fetch data for the current view
$ayahs = [];
$randomAyahs = [];
$searchResults = [];
$totalSearchResults = 0;
$searchTotalPages = 0;
$bookmarks = [];
$users = [];
$analytics = [];

$totalAyahs = getTotalAyahs();
$totalPages = ceil($totalAyahs / ITEMS_PER_PAGE);
$page = max(1, min($page, $totalPages)); // Recalculate clamped page after potential changes


if ($action === 'read') {
    $ayahs = getAyahsPage($page);
    if (empty($ayahs) && $totalAyahs > 0) {
        // Handle case where requested page might be invalid after data changes/errors
        error_log("Warning: No ayahs found for page $page. Resetting to page 1.");
        $page = 1;
        $_SESSION['current_surah'] = 1;
        $_SESSION['current_ayah'] = 1;
        $ayahs = getAyahsPage($page); // Try fetching page 1
    }
     // Ensure session reflects the first ayah of the *actually* displayed page
     if (!empty($ayahs)) {
         $_SESSION['current_surah'] = $ayahs[0]['surah_number'];
         $_SESSION['current_ayah'] = $ayahs[0]['ayah_number'];
         // Save progress again after potential correction
         if (isLoggedIn()) { saveUserProgress(); }
     } elseif ($totalAyahs == 0) {
          $errorMessage .= " No Ayah data found in the database. Please check data import.";
     }

} elseif ($action === 'search' && !empty($searchQuery)) {
    $searchData = searchAyahs($searchQuery, $searchPage);
    $searchResults = $searchData['results'];
    $totalSearchResults = $searchData['total'];
    if ($totalSearchResults > 0) {
       $searchTotalPages = ceil($totalSearchResults / SEARCH_RESULTS_PER_PAGE);
       $searchPage = max(1, min($searchPage, $searchTotalPages)); // Clamp search page
    } else {
        $searchTotalPages = 0;
        $searchPage = 1;
    }

} elseif ($action === 'bookmarks' && isLoggedIn()) {
    $bookmarks = getUserBookmarks($_SESSION['user_id']);

} elseif ($action === 'admin' && isAdmin()) {
    $users = getAllUsers();
    $analytics = getAnalytics();
}

// Always load some random ayahs for the sidebar/initial display if applicable
$randomAyahsSidebar = getRandomAyahs(5);

?>
<!DOCTYPE html>
<html lang="ur" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo sanitize(APP_NAME); ?></title>
    <link href="https://fonts.googleapis.com/css2?family=Amiri:wght@400;700&family=Noto+Nastaliq+Urdu:wght@400;700&display=swap" rel="stylesheet">
    <script src="https://cdn.tailwindcss.com?plugins=forms,typography"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        /* Base font */
        body { font-family: 'Noto Nastaliq Urdu', serif; line-height: 1.8; }
        /* Specific font classes */
        .font-amiri { font-family: 'Amiri', serif; }
        .font-urdu { font-family: 'Noto Nastaliq Urdu', serif; }

        /* Basic RTL adjustments if Tailwind's dir attribute isn't sufficient (rarely needed) */
        /* Removed custom RTL swaps for padding/margin/text-align as Tailwind handles it */

         /* Futuristic Theme & Dark Mode */
        :root {
            --bg-light: #f8fafc; /* slate-50 */
            --text-light: #1e293b; /* slate-800 */
            --primary-light: #16a34a; /* green-600 */
            --secondary-light: #ca8a04; /* yellow-600 */
            --accent-light: #4ade80; /* green-400 */
            --border-light: #e2e8f0; /* slate-200 */
            --glass-bg-light: rgba(255, 255, 255, 0.2);
            --glass-border-light: rgba(255, 255, 255, 0.3);

            --bg-dark: #0f172a; /* slate-900 */
            --text-dark: #e2e8f0; /* slate-200 */
            --primary-dark: #22c55e; /* green-500 */
            --secondary-dark: #eab308; /* yellow-500 */
            --accent-dark: #166534; /* green-800 */
            --border-dark: #334155; /* slate-700 */
            --glass-bg-dark: rgba(15, 23, 42, 0.4); /* Slightly more opaque */
            --glass-border-dark: rgba(51, 65, 85, 0.6);

            --bg-color: var(--bg-light);
            --text-color: var(--text-light);
            --primary-color: var(--primary-light);
            --secondary-color: var(--secondary-light);
            --accent-color: var(--accent-light);
            --border-color: var(--border-light);
            --glass-bg: var(--glass-bg-light);
            --glass-border: var(--glass-border-light);
        }
        html.dark {
             --bg-color: var(--bg-dark);
            --text-color: var(--text-dark);
            --primary-color: var(--primary-dark);
            --secondary-color: var(--secondary-dark);
            --accent-color: var(--accent-dark);
            --border-color: var(--border-dark);
             --glass-bg: var(--glass-bg-dark);
            --glass-border: var(--glass-border-dark);
        }
         body {
            background-color: var(--bg-color);
            color: var(--text-color);
            transition: background-color 0.3s ease, color 0.3s ease;
        }
        .bg-theme { background-color: var(--bg-color); }
        .text-theme { color: var(--text-color); }
        .border-theme { border-color: var(--border-color); }
        .bg-primary { background-color: var(--primary-color); }
        .text-primary { color: var(--primary-color); }
        .bg-secondary { background-color: var(--secondary-color); }
        .text-secondary { color: var(--secondary-color); }
        .bg-accent { background-color: var(--accent-color); }
        .border-primary { border-color: var(--primary-color); }
        .hover\:bg-accent:hover { background-color: var(--accent-color); }
        .hover\:text-secondary:hover { color: var(--secondary-color); }
        .shadow-glow { box-shadow: 0 0 15px rgba(34, 197, 94, 0.5); /* Adjust color */ }
        html.dark .shadow-glow { box-shadow: 0 0 15px rgba(74, 222, 128, 0.6); }

        .btn { @apply inline-flex items-center justify-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium focus:outline-none focus:ring-2 focus:ring-offset-2 transition-colors duration-200; }
        .btn-primary { @apply text-white bg-primary hover:bg-green-700 dark:hover:bg-green-600 focus:ring-primary; }
        .btn-secondary { @apply text-white bg-secondary hover:opacity-90 focus:ring-secondary; }
        .btn-outline { @apply text-primary bg-transparent border border-primary hover:bg-primary/10 focus:ring-primary; }
        .btn-icon { @apply p-2 rounded-full hover:bg-primary/10 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary/50 text-primary; }
        .btn-icon.active { @apply bg-primary/20 text-secondary; }

        .glassmorphism {
           background: var(--glass-bg);
           backdrop-filter: blur(10px);
           -webkit-backdrop-filter: blur(10px);
           border: 1px solid var(--glass-border);
           border-radius: 16px;
        }
         .ayah-card {
            @apply border-b border-dashed border-theme p-4 md:p-6 transition-colors duration-300;
            scroll-margin-top: 80px; /* Offset for sticky header */
         }
          .ayah-card:last-child { @apply border-b-0; }
          .ayah-card:hover, .ayah-card.highlight { background-color: rgba(var(--primary-rgb, 34, 197, 94), 0.1); } /* Use RGBA for hover background */
          html.dark .ayah-card:hover, html.dark .ayah-card.highlight { background-color: rgba(var(--primary-rgb-dark, 34, 197, 94), 0.2); } /* Dark mode hover */

          /* Add :focus-visible styles for accessibility */
         *:focus-visible {
             @apply outline-none ring-2 ring-offset-2 ring-secondary;
         }
         /* Basic input styling */
        input[type="text"], input[type="email"], input[type="password"], select {
             @apply block w-full px-4 py-2 rounded-md border border-theme bg-theme/50 focus:ring-primary focus:border-primary text-theme placeholder-gray-500;
         }
         label { @apply block text-sm font-medium text-theme mb-1 text-right; } /* Ensure labels are right-aligned */

         /* Tailwind utility for explicit right alignment */
         .text-right { text-align: right !important; }

         /* Responsive adjustments */
         @media (max-width: 768px) {
             .ayah-card { padding: 1rem; } /* Less padding on mobile */
             .font-amiri { font-size: 1.25rem; } /* Slightly smaller Arabic on mobile */
             .font-urdu { font-size: 1rem; } /* Slightly smaller Urdu on mobile */
         }

    </style>
</head>
<body class="bg-theme text-theme">

    <header class="sticky top-0 z-50 shadow-md glassmorphism">
        <nav class="container mx-auto px-4 py-3 flex flex-wrap items-center justify-between gap-y-2">
            {/* */}
            <a href="index.php" class="text-2xl font-bold text-primary flex items-center space-x-2 rtl:space-x-reverse">
                 <i class="fas fa-book-quran"></i>
                 <span><?php echo sanitize(APP_NAME); ?></span>
            </a>

            {/* */}
            <div class="hidden md:flex items-center space-x-2 rtl:space-x-reverse">
                <form action="index.php" method="get" class="relative">
                    <input type="hidden" name="action" value="search">
                    {/* */}
                    <input type="text" name="q" placeholder="تلاش کریں (عربی/اردو)" value="<?php echo sanitize($searchQuery); ?>"
                           class="py-2 pl-10 pr-4 rounded-full border border-theme bg-theme/50 focus:ring-primary focus:border-primary text-sm text-right" style="width: 250px;">
                    <button type="submit" class="absolute inset-y-0 left-0 flex items-center pl-3 text-primary hover:text-secondary">
                        <i class="fas fa-search"></i>
                    </button>
                </form>

                 <button id="darkModeToggle" class="btn-icon text-secondary" title="Toggle Dark Mode">
                     <i class="fas fa-moon"></i>
                 </button>

                <?php if (isLoggedIn()): ?>
                    <div class="relative group">
                       <button class="btn-icon text-primary">
                          <i class="fas fa-user"></i>
                       </button>
                       {/* */}
                        <div class="absolute left-0 mt-2 w-48 bg-theme rounded-md shadow-lg py-1 z-50 hidden group-hover:block border border-theme text-right">
                             <span class="block px-4 py-2 text-sm text-gray-500"><?php echo sanitize($current_user['email'] ?? ''); ?></span>
                             <a href="index.php?action=bookmarks" class="block px-4 py-2 text-sm text-theme hover:bg-primary/10">میرے بوک مارکس</a>
                             <?php if (isAdmin()): ?>
                             <a href="index.php?action=admin" class="block px-4 py-2 text-sm text-theme hover:bg-primary/10">ایڈمن ڈیش بورڈ</a>
                             <?php endif; ?>
                             <a href="index.php?action=logout" class="block px-4 py-2 text-sm text-red-500 hover:bg-red-500/10">لاگ آؤٹ</a>
                        </div>
                    </div>

                <?php else: ?>
                    <a href="index.php?action=login" class="btn btn-outline text-sm">لاگ ان</a>
                    <a href="index.php?action=register" class="btn btn-primary text-sm">رجسٹر</a>
                <?php endif; ?>
            </div>

            {/* */}
            <form action="index.php" method="get" class="relative w-full md:hidden order-last">
                 <input type="hidden" name="action" value="search">
                 {/* */}
                 <input type="text" name="q" placeholder="تلاش کریں (عربی/اردو)" value="<?php echo sanitize($searchQuery); ?>"
                        class="w-full py-2 pl-10 pr-4 rounded-full border border-theme bg-theme/50 focus:ring-primary focus:border-primary text-sm text-right">
                 <button type="submit" class="absolute inset-y-0 left-0 flex items-center pl-3 text-primary hover:text-secondary">
                     <i class="fas fa-search"></i>
                 </button>
            </form>

             {/* */}
             <div class="flex md:hidden items-center space-x-2 rtl:space-x-reverse">
                 <button id="darkModeToggleMobile" class="btn-icon text-secondary" title="Toggle Dark Mode">
                     <i class="fas fa-moon"></i>
                 </button>
                  <?php if (isLoggedIn()): ?>
                     <div class="relative group">
                       <button class="btn-icon text-primary">
                          <i class="fas fa-user"></i>
                       </button>
                        <div class="absolute left-0 mt-2 w-48 bg-theme rounded-md shadow-lg py-1 z-50 hidden group-hover:block border border-theme text-right">
                             <span class="block px-4 py-2 text-sm text-gray-500"><?php echo sanitize($current_user['email'] ?? ''); ?></span>
                             <a href="index.php?action=bookmarks" class="block px-4 py-2 text-sm text-theme hover:bg-primary/10">میرے بوک مارکس</a>
                             <?php if (isAdmin()): ?>
                             <a href="index.php?action=admin" class="block px-4 py-2 text-sm text-theme hover:bg-primary/10">ایڈمن ڈیش بورڈ</a>
                             <?php endif; ?>
                             <a href="index.php?action=logout" class="block px-4 py-2 text-sm text-red-500 hover:bg-red-500/10">لاگ آؤٹ</a>
                        </div>
                    </div>
                 <?php else: ?>
                    <a href="index.php?action=login" class="btn btn-outline text-sm">لاگ ان</a>
                    {/* */}
                    {/* <a href="index.php?action=register" class="btn btn-primary text-sm">رجسٹر</a> */}
                 <?php endif; ?>
             </div>
        </nav>
    </header>

    <main class="container mx-auto px-4 py-6">

        <?php if ($errorMessage): ?>
        <div class="mb-4 p-4 bg-red-100 border border-red-400 text-red-700 rounded text-right" role="alert">
            <span class="block sm:inline"><?php echo sanitize($errorMessage); ?></span>
        </div>
        <?php endif; ?>
        <?php if ($successMessage): ?>
        <div class="mb-4 p-4 bg-green-100 border border-green-400 text-green-700 rounded text-right" role="alert">
            <span class="block sm:inline"><?php echo sanitize($successMessage); ?></span>
        </div>
        <?php endif; ?>


        <?php if ($action === 'read'): ?>
            <div class="grid grid-cols-1 md:grid-cols-4 gap-6">
                <div class="md:col-span-3">
                     <div class="bg-theme rounded-lg shadow-lg overflow-hidden glassmorphism mb-6">
                         <?php if (!empty($ayahs)): ?>
                             <?php foreach ($ayahs as $ayahItem):
                                   $isBookmarked = isLoggedIn() && isBookmarked($_SESSION['user_id'], $ayahItem['surah_number'], $ayahItem['ayah_number']);
                             ?>
                                 <div id="ayah-<?php echo $ayahItem['surah_number'] . '-' . $ayahItem['ayah_number']; ?>" class="ayah-card flex flex-col space-y-4 text-right">
                                     {/* */}
                                     <p class="font-amiri text-xl md:text-2xl leading-loose">
                                         <?php echo $ayahItem['arabic_text']; ?>
                                         <span class="text-sm font-sans text-secondary mr-2">(<?php echo $ayahItem['surah_number'] . ':' . $ayahItem['ayah_number']; ?>)</span>
                                     </p>
                                     {/* */}
                                     <p class="font-urdu text-lg md:text-xl leading-relaxed">
                                         ترجمہ: <?php echo $ayahItem['urdu_translation']; ?>
                                     </p>
                                     {/* */}
                                     <div class="flex items-center justify-end space-x-2 rtl:space-x-reverse mt-2">
                                          <a href="index.php?action=set_read_point&surah=<?php echo $ayahItem['surah_number']; ?>&ayah=<?php echo $ayahItem['ayah_number']; ?>" title="یہاں سے پڑھیں" class="btn-icon text-sm">
                                              <i class="fas fa-book-open-reader"></i>
                                          </a>
                                         <?php if (isLoggedIn()): ?>
                                             <button onclick="playAudio(<?php echo $ayahItem['global_ayah_number']; ?>, this)" title="سنیں" class="btn-icon text-sm audio-btn" data-active="false">
                                                 <i class="fas fa-play"></i>
                                             </button>
                                              <form action="index.php" method="post" class="inline">
                                                 <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                                 <input type="hidden" name="action" value="bookmark">
                                                 <input type="hidden" name="surah" value="<?php echo $ayahItem['surah_number']; ?>">
                                                 <input type="hidden" name="ayah" value="<?php echo $ayahItem['ayah_number']; ?>">
                                                 <input type="hidden" name="current_page" value="<?php echo $page; ?>"> {/* Pass current page */}
                                                 <button type="submit" name="<?php echo $isBookmarked ? 'remove' : 'add'; ?>" title="<?php echo $isBookmarked ? 'بوک مارک ہٹائیں' : 'بوک مارک کریں'; ?>" class="btn-icon text-sm <?php echo $isBookmarked ? 'text-yellow-500' : 'text-primary'; ?>">
                                                     <i class="<?php echo $isBookmarked ? 'fas' : 'far'; ?> fa-bookmark"></i>
                                                 </button>
                                             </form>
                                         <?php endif; ?>
                                     </div>
                                 </div>
                             <?php endforeach; ?>
                         <?php else: ?>
                              <div class="p-6 text-center text-gray-500">کوئی آیات نہیں ملیں۔ ڈیٹا بیس خالی ہو سکتا ہے۔</div>
                         <?php endif; ?>
                     </div>

                     <?php if ($totalPages > 1): ?>
                         <div class="flex justify-between items-center mt-6">
                             <?php if ($page > 1): ?>
                                 <a href="index.php?action=read&page=<?php echo $page - 1; ?>" class="btn btn-outline">« پچھلا</a>
                             <?php else: ?>
                                  <span class="btn btn-outline opacity-50 cursor-not-allowed">« پچھلا</span>
                             <?php endif; ?>

                             <span class="text-sm text-gray-500">صفحہ <?php echo $page; ?> از <?php echo $totalPages; ?></span>

                             <?php if ($page < $totalPages): ?>
                                 <a href="index.php?action=read&page=<?php echo $page + 1; ?>" class="btn btn-outline">اگلا »</a>
                              <?php else: ?>
                                  <span class="btn btn-outline opacity-50 cursor-not-allowed">اگلا »</span>
                             <?php endif; ?>
                         </div>
                      <?php endif; ?>
                      <audio id="audioPlayer" controls class="w-full mt-4 hidden"></audio>
                </div>

                <div class="md:col-span-1 space-y-6">
                     <div class="bg-theme rounded-lg shadow p-4 glassmorphism text-right">
                        <h3 class="text-lg font-semibold mb-3 border-b border-primary pb-2 text-primary">موجودہ مقام</h3>
                         <p class="text-sm">سورہ <?php echo sanitize($_SESSION['current_surah'] ?? 1); ?>, آیت <?php echo sanitize($_SESSION['current_ayah'] ?? 1); ?></p>
                         <?php if(isLoggedIn() && $current_user): ?>
                           <p class="text-xs text-gray-400 mt-1">(محفوظ شدہ)</p>
                         <?php else: ?>
                            <p class="text-xs text-gray-400 mt-1">(سیشن)</p>
                         <?php endif; ?>
                     </div>

                    <div class="bg-theme rounded-lg shadow p-4 glassmorphism text-right">
                        <h3 class="text-lg font-semibold mb-3 border-b border-primary pb-2 text-primary">بے ترتیب آیات</h3>
                         <div class="space-y-3">
                             <?php foreach ($randomAyahsSidebar as $randAyah): ?>
                                 <div class="text-sm border-b border-dashed border-theme/50 pb-2">
                                      <p class="font-amiri text-right leading-relaxed"><?php echo $randAyah['arabic_text']; ?></p>
                                      <a href="index.php?action=read&surah=<?php echo $randAyah['surah_number']; ?>&ayah=<?php echo $randAyah['ayah_number']; ?>" class="block mt-1 text-xs text-secondary hover:underline">
                                          (<?php echo $randAyah['surah_number']; ?>:<?php echo $randAyah['ayah_number']; ?>) مزید پڑھیں
                                      </a>
                                 </div>
                             <?php endforeach; ?>
                              <a href="index.php?action=random" class="block text-center mt-2 text-sm btn btn-secondary w-full">10 اور دیکھیں</a>
                         </div>
                    </div>
                </div>
            </div>

        <?php elseif ($action === 'search'): ?>
            <h2 class="text-2xl font-semibold mb-6 text-primary text-right">تلاش کے نتائج برائے: "<?php echo sanitize($searchQuery); ?>"</h2>
             <?php if (empty($searchResults)): ?>
                <p class="text-right">کوئی نتیجہ نہیں ملا۔</p>
             <?php else: ?>
                 <div class="bg-theme rounded-lg shadow-lg overflow-hidden glassmorphism mb-6">
                     <?php foreach ($searchResults as $ayahItem):
                         $isBookmarked = isLoggedIn() && isBookmarked($_SESSION['user_id'], $ayahItem['surah_number'], $ayahItem['ayah_number']);
                         $current_page_for_redirect = getPageNumberForAyah($ayahItem['surah_number'], $ayahItem['ayah_number']); // Get page for redirect
                     ?>
                       <div id="ayah-<?php echo $ayahItem['surah_number'] . '-' . $ayahItem['ayah_number']; ?>" class="ayah-card flex flex-col space-y-4 text-right">
                            <p class="font-amiri text-xl md:text-2xl leading-loose">
                                <?php
                                   // Highlight search term in Arabic
                                   $highlighted_arabic = preg_replace('/(' . preg_quote(sanitize($searchQuery), '/') . ')/iu', '<span class="bg-yellow-300 dark:bg-yellow-600 px-1">$1</span>', $ayahItem['arabic_text']);
                                   echo $highlighted_arabic;
                                 ?>
                                 <span class="text-sm font-sans text-secondary mr-2">(<?php echo $ayahItem['surah_number'] . ':' . $ayahItem['ayah_number']; ?>)</span>
                            </p>
                            <p class="font-urdu text-lg md:text-xl leading-relaxed">
                                ترجمہ: <?php
                                   // Highlight search term in Urdu
                                   $highlighted_urdu = preg_replace('/(' . preg_quote(sanitize($searchQuery), '/') . ')/iu', '<span class="bg-yellow-300 dark:bg-yellow-600 px-1">$1</span>', $ayahItem['urdu_translation']);
                                   echo $highlighted_urdu;
                                 ?>
                            </p>
                            <div class="flex items-center justify-end space-x-2 rtl:space-x-reverse mt-2">
                                <a href="index.php?action=read&surah=<?php echo $ayahItem['surah_number']; ?>&ayah=<?php echo $ayahItem['ayah_number']; ?>" title="مکمل آیت پڑھیں" class="btn-icon text-sm">
                                    <i class="fas fa-eye"></i>
                                </a>
                                <a href="index.php?action=set_read_point&surah=<?php echo $ayahItem['surah_number']; ?>&ayah=<?php echo $ayahItem['ayah_number']; ?>" title="یہاں سے پڑھیں" class="btn-icon text-sm">
                                    <i class="fas fa-book-open-reader"></i>
                                </a>
                                <?php if (isLoggedIn()): ?>
                                    <button onclick="playAudio(<?php echo $ayahItem['global_ayah_number']; ?>, this)" title="سنیں" class="btn-icon text-sm audio-btn" data-active="false">
                                        <i class="fas fa-play"></i>
                                    </button>
                                    <form action="index.php" method="post" class="inline">
                                       <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                       <input type="hidden" name="action" value="bookmark">
                                       <input type="hidden" name="surah" value="<?php echo $ayahItem['surah_number']; ?>">
                                       <input type="hidden" name="ayah" value="<?php echo $ayahItem['ayah_number']; ?>">
                                       <input type="hidden" name="current_page" value="<?php echo $current_page_for_redirect; ?>"> {/* Pass target page */}
                                       <button type="submit" name="<?php echo $isBookmarked ? 'remove' : 'add'; ?>" title="<?php echo $isBookmarked ? 'بوک مارک ہٹائیں' : 'بوک مارک کریں'; ?>" class="btn-icon text-sm <?php echo $isBookmarked ? 'text-yellow-500' : 'text-primary'; ?>">
                                           <i class="<?php echo $isBookmarked ? 'fas' : 'far'; ?> fa-bookmark"></i>
                                       </button>
                                   </form>
                                <?php endif; ?>
                            </div>
                        </div>
                     <?php endforeach; ?>
                 </div>
                  <audio id="audioPlayer" controls class="w-full mt-4 hidden"></audio>

                 <?php if ($searchTotalPages > 1): ?>
                 <div class="flex justify-between items-center mt-6">
                       <?php if ($searchPage > 1): ?>
                           <a href="index.php?action=search&q=<?php echo urlencode($searchQuery); ?>&spage=<?php echo $searchPage - 1; ?>" class="btn btn-outline">« پچھلا</a>
                       <?php else: ?>
                            <span class="btn btn-outline opacity-50 cursor-not-allowed">« پچھلا</span>
                       <?php endif; ?>

                       <span class="text-sm text-gray-500">صفحہ <?php echo $searchPage; ?> از <?php echo $searchTotalPages; ?> (کل <?php echo $totalSearchResults; ?> نتائج)</span>

                       <?php if ($searchPage < $searchTotalPages): ?>
                           <a href="index.php?action=search&q=<?php echo urlencode($searchQuery); ?>&spage=<?php echo $searchPage + 1; ?>" class="btn btn-outline">اگلا »</a>
                        <?php else: ?>
                           <span class="btn btn-outline opacity-50 cursor-not-allowed">اگلا »</span>
                       <?php endif; ?>
                   </div>
                 <?php endif; ?>

            <?php endif; ?>


        <?php elseif ($action === 'login'): ?>
             <div class="max-w-md mx-auto mt-10 bg-theme rounded-lg shadow-lg p-8 glassmorphism">
                 <h2 class="text-2xl font-semibold text-center mb-6 text-primary">لاگ ان</h2>
                 <form action="index.php" method="post" class="space-y-4 text-right">
                     <input type="hidden" name="action" value="login">
                     <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                     <div>
                         <label for="login_email">ای میل</label>
                         <input type="email" id="login_email" name="email" required>
                     </div>
                     <div>
                         <label for="login_password">پاس ورڈ</label>
                         <input type="password" id="login_password" name="password" required>
                     </div>
                     <button type="submit" class="w-full btn btn-primary">لاگ ان کریں</button>
                     <p class="text-sm text-center text-gray-500 mt-4">
                         اکاؤنٹ نہیں ہے؟ <a href="index.php?action=register" class="text-primary hover:underline">رجسٹر کریں</a>
                     </p>
                 </form>
             </div>

        <?php elseif ($action === 'register'): ?>
            <div class="max-w-md mx-auto mt-10 bg-theme rounded-lg shadow-lg p-8 glassmorphism">
                <h2 class="text-2xl font-semibold text-center mb-6 text-primary">نیا اکاؤنٹ بنائیں</h2>
                <form action="index.php" method="post" class="space-y-4 text-right">
                    <input type="hidden" name="action" value="register">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                    <div>
                        <label for="register_email">ای میل</label>
                        <input type="email" id="register_email" name="email" required>
                    </div>
                    <div>
                        <label for="register_password">پاس ورڈ (کم از کم 6 حروف)</label>
                        <input type="password" id="register_password" name="password" required minlength="6">
                    </div>
                    <button type="submit" class="w-full btn btn-primary">رجسٹر کریں</button>
                     <p class="text-sm text-center text-gray-500 mt-4">
                         پہلے سے اکاؤنٹ ہے؟ <a href="index.php?action=login" class="text-primary hover:underline">لاگ ان کریں</a>
                     </p>
                </form>
            </div>

        <?php elseif ($action === 'bookmarks' && isLoggedIn()): ?>
             <h2 class="text-2xl font-semibold mb-6 text-primary text-right">میرے بوک مارکس</h2>
             <?php if (empty($bookmarks)): ?>
                 <p class="text-right">آپ نے ابھی تک کوئی آیت بوک مارک نہیں کی ہے۔</p>
             <?php else: ?>
                 <div class="bg-theme rounded-lg shadow-lg overflow-hidden glassmorphism mb-6">
                     <?php foreach ($bookmarks as $bookmark):
                          $current_page_for_redirect = getPageNumberForAyah($bookmark['surah_number'], $bookmark['ayah_number']); // Get page for redirect
                     ?>
                          <div class="ayah-card flex flex-col md:flex-row md:items-center justify-between space-y-4 md:space-y-0 text-right">
                             <div class="flex-grow">
                                  <p class="font-amiri text-xl leading-loose">
                                     <?php echo $bookmark['arabic_text']; ?>
                                     <span class="text-sm font-sans text-secondary mr-2">(<?php echo $bookmark['surah_number'] . ':' . $bookmark['ayah_number']; ?>)</span>
                                  </p>
                                  <p class="font-urdu text-lg leading-relaxed mt-2">
                                     ترجمہ: <?php echo $bookmark['urdu_translation']; ?>
                                 </p>
                             </div>
                              {/* */}
                              <div class="flex items-center justify-end md:justify-start space-x-2 rtl:space-x-reverse flex-shrink-0 md:ml-4"> {/* Add margin for spacing */}
                                   <a href="index.php?action=read&surah=<?php echo $bookmark['surah_number']; ?>&ayah=<?php echo $bookmark['ayah_number']; ?>" title="آیت پر جائیں" class="btn-icon text-sm">
                                      <i class="fas fa-eye"></i>
                                  </a>
                                  <form action="index.php" method="post" class="inline">
                                      <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                      <input type="hidden" name="action" value="bookmark">
                                      <input type="hidden" name="surah" value="<?php echo $bookmark['surah_number']; ?>">
                                      <input type="hidden" name="ayah" value="<?php echo $bookmark['ayah_number']; ?>">
                                       <input type="hidden" name="current_page" value="<?php echo $current_page_for_redirect; ?>"> {/* Pass target page */}
                                      <button type="submit" name="remove" title="بوک مارک ہٹائیں" class="btn-icon text-sm text-red-500">
                                          <i class="fas fa-trash-alt"></i>
                                      </button>
                                  </form>
                             </div>
                         </div>
                     <?php endforeach; ?>
                 </div>
             <?php endif; ?>


         <?php elseif ($action === 'admin' && isAdmin()): ?>
              <h2 class="text-2xl font-semibold mb-6 text-primary text-right">ایڈمن ڈیش بورڈ</h2>

               <div class="mb-8 p-6 bg-theme rounded-lg shadow-lg glassmorphism text-right">
                  <h3 class="text-xl font-semibold mb-4 border-b border-secondary pb-2 text-secondary">سائٹ کے اعداد و شمار</h3>
                  <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4">
                      <?php foreach ($analytics as $key => $value): ?>
                          <div class="bg-theme/50 p-4 rounded border border-theme text-center">
                              <div class="text-2xl font-bold text-primary"><?php echo sanitize($value); ?></div>
                              <div class="text-sm text-gray-500"><?php echo sanitize($key); ?></div>
                          </div>
                      <?php endforeach; ?>
                  </div>
              </div>

               <div class="bg-theme rounded-lg shadow-lg overflow-hidden glassmorphism">
                  <h3 class="text-xl font-semibold p-4 border-b border-secondary text-secondary text-right">صارفین کا انتظام</h3>
                  <div class="overflow-x-auto">
                      <table class="min-w-full divide-y divide-border-theme text-right">
                          <thead class="bg-theme/30">
                              <tr>
                                  <th scope="col" class="px-6 py-3 text-xs font-medium text-theme uppercase tracking-wider">ID</th>
                                  <th scope="col" class="px-6 py-3 text-xs font-medium text-theme uppercase tracking-wider">ای میل</th>
                                  <th scope="col" class="px-6 py-3 text-xs font-medium text-theme uppercase tracking-wider">کردار</th>
                                  <th scope="col" class="px-6 py-3 text-center text-xs font-medium text-theme uppercase tracking-wider">اعمال</th>
                              </tr>
                          </thead>
                          <tbody class="bg-theme divide-y divide-border-theme">
                              <?php foreach ($users as $user): ?>
                                  <tr>
                                      <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-theme"><?php echo $user['id']; ?></td>
                                      <td class="px-6 py-4 whitespace-nowrap text-sm text-theme"><?php echo sanitize($user['email']); ?></td>
                                      <td class="px-6 py-4 whitespace-nowrap text-sm text-theme">
                                           <form action="index.php" method="post" class="inline">
                                               <input type="hidden" name="action" value="update_role">
                                               <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                               <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
                                               <select name="role" onchange="this.form.submit()" class="rounded border border-theme bg-theme/50 text-sm p-1 text-right" <?php echo ($user['id'] == $_SESSION['user_id']) ? 'disabled' : ''; ?>>
                                                  <option value="<?php echo ROLE_USER; ?>" <?php echo ($user['role'] == ROLE_USER) ? 'selected' : ''; ?>><?php echo ROLE_USER; ?></option>
                                                  <option value="<?php echo ROLE_ADMIN; ?>" <?php echo ($user['role'] == ROLE_ADMIN) ? 'selected' : ''; ?>><?php echo ROLE_ADMIN; ?></option>
                                               </select>
                                           </form>
                                       </td>
                                      <td class="px-6 py-4 whitespace-nowrap text-center text-sm font-medium">
                                          <?php if ($user['id'] != $_SESSION['user_id']): ?>
                                             <form action="index.php" method="post" class="inline" onsubmit="return confirm('کیا آپ واقعی اس صارف کو حذف کرنا چاہتے ہیں؟');">
                                                 <input type="hidden" name="action" value="delete_user">
                                                 <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                                 <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
                                                 <button type="submit" class="text-red-600 hover:text-red-900" title="صارف حذف کریں">
                                                      <i class="fas fa-trash-alt"></i>
                                                 </button>
                                             </form>
                                         <?php else: ?>
                                            <span class="text-gray-400 cursor-not-allowed" title="آپ خود کو حذف نہیں کر سکتے"><i class="fas fa-trash-alt"></i></span>
                                         <?php endif; ?>
                                      </td>
                                  </tr>
                              <?php endforeach; ?>
                          </tbody>
                      </table>
                   </div>
               </div>
         <?php endif; ?>

    </main>

    <footer class="mt-12 py-6 border-t border-theme text-center text-sm text-gray-500">
         &copy; <?php echo date("Y"); ?> <?php echo sanitize(APP_NAME); ?>. تمام حقوق محفوظ ہیں۔
    </footer>

    <script>
        const audioPlayer = document.getElementById('audioPlayer');
        let currentlyPlayingButton = null;

         function playAudio(globalAyahNumber, buttonElement) {
             const audioUrl = `https://cdn.alquran.cloud/media/audio/ayah/ar.alafasy/${globalAyahNumber}`;
             const isPlaying = buttonElement === currentlyPlayingButton;

             // Stop any currently playing audio and reset its button
             if (currentlyPlayingButton && currentlyPlayingButton !== buttonElement) {
                 audioPlayer.pause();
                 currentlyPlayingButton.innerHTML = '<i class="fas fa-play"></i>';
                 currentlyPlayingButton.classList.remove('active');
                 currentlyPlayingButton.setAttribute('data-active', 'false');
             }

             if (isPlaying && !audioPlayer.paused) {
                 // Pause the current audio
                 audioPlayer.pause();
                 buttonElement.innerHTML = '<i class="fas fa-play"></i>';
                 buttonElement.classList.remove('active');
                 buttonElement.setAttribute('data-active', 'false');
                 currentlyPlayingButton = null;
                 audioPlayer.classList.add('hidden'); // Hide player when paused explicitly
             } else {
                 // Start playing new audio or resume paused
                 audioPlayer.src = audioUrl; // Set source even if resuming
                 audioPlayer.classList.remove('hidden');
                 audioPlayer.play().then(() => {
                      // Update button state on successful play
                      buttonElement.innerHTML = '<i class="fas fa-pause"></i>';
                      buttonElement.classList.add('active');
                      buttonElement.setAttribute('data-active', 'true');
                      currentlyPlayingButton = buttonElement;
                 }).catch(e => {
                     console.error("Audio playback failed:", e);
                     audioPlayer.classList.add('hidden');
                     // Reset button if play fails
                     buttonElement.innerHTML = '<i class="fas fa-play"></i>';
                      buttonElement.classList.remove('active');
                     buttonElement.setAttribute('data-active', 'false');
                     currentlyPlayingButton = null; // Ensure no button seems active
                 });
             }
         }

         // Reset button when audio ends naturally
         audioPlayer.onended = () => {
             if (currentlyPlayingButton) {
                 currentlyPlayingButton.innerHTML = '<i class="fas fa-play"></i>';
                 currentlyPlayingButton.classList.remove('active');
                 currentlyPlayingButton.setAttribute('data-active', 'false');
             }
             currentlyPlayingButton = null;
             audioPlayer.classList.add('hidden');
         };

          // Reset button if paused via player controls (optional, could leave as pause)
         // audioPlayer.onpause = () => {
         //     // Check if pause was not triggered by clicking the button again (which is handled above)
         //     // and not at the end of the track (handled by onended)
         //     if (currentlyPlayingButton && audioPlayer.currentTime > 0 && !audioPlayer.ended) {
         //        // console.log("Paused via controls");
         //         // currentlyPlayingButton.innerHTML = '<i class="fas fa-play"></i>';
         //        // currentlyPlayingButton = null; // Decide if controls pause should reset the button
         //     }
         // };


         // Dark Mode Toggle Logic (for both buttons)
         const darkModeToggles = document.querySelectorAll('#darkModeToggle, #darkModeToggleMobile');
         const htmlElement = document.documentElement;

         function setDarkMode(isDark) {
             if (isDark) {
                 htmlElement.classList.add('dark');
                 localStorage.setItem('theme', 'dark');
                 darkModeToggles.forEach(toggle => toggle.innerHTML = '<i class="fas fa-sun"></i>');
                  // Define RGB for dark mode primary color (#22c55e -> 34, 197, 94)
                 document.documentElement.style.setProperty('--primary-rgb-dark', '34, 197, 94');
             } else {
                 htmlElement.classList.remove('dark');
                 localStorage.setItem('theme', 'light');
                 darkModeToggles.forEach(toggle => toggle.innerHTML = '<i class="fas fa-moon"></i>');
                  // Define RGB for light mode primary color (#16a34a -> 22, 163, 74)
                 document.documentElement.style.setProperty('--primary-rgb', '22, 163, 74');
             }
         }

         // Initial theme setup
         const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
         const savedTheme = localStorage.getItem('theme');
         setDarkMode(savedTheme === 'dark' || (savedTheme === null && prefersDark));

         // Add event listener to toggles
         darkModeToggles.forEach(toggle => {
             toggle.addEventListener('click', () => {
                 setDarkMode(!htmlElement.classList.contains('dark'));
             });
         });


          // Smooth scroll to hash targets and highlight
         document.addEventListener('DOMContentLoaded', () => {
            if (window.location.hash && window.location.hash.startsWith('#ayah-')) {
                 try {
                     const targetElement = document.querySelector(window.location.hash);
                     if (targetElement) {
                          setTimeout(() => { // Timeout ensures layout is stable
                             targetElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
                              // Add a temporary highlight class
                              targetElement.classList.add('highlight');
                              setTimeout(() => {
                                   targetElement.classList.remove('highlight');
                              }, 2500); // Remove highlight after 2.5 seconds
                          }, 150); // Slightly longer timeout
                     }
                 } catch (e) {
                      console.error("Error scrolling to hash:", e); // Catch potential invalid selector errors
                 }
            }
         });

    </script>
</body>
</html>