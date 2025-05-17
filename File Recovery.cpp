#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <memory>
#include <cstring>
#include <filesystem>
#include <system_error>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <unordered_set>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#endif

using namespace std;
namespace fs = std::filesystem;

struct FileSignature {
    string extension;
    vector<unsigned char> header;
    vector<unsigned char> footer;
    size_t min_size;
    size_t max_size;
};

const vector<FileSignature> SIGNATURES = {
    // PDF
    {"pdf", {0x25, 0x50, 0x44, 0x46}, {0x25, 0x25, 0x45, 0x4F, 0x46}, 100, 50'000'000},
    
    // JPEG
    {"jpg", {0xFF, 0xD8, 0xFF}, {0xFF, 0xD9}, 100, 20'000'000},
    
    // PNG
    {"png", {0x89, 0x50, 0x4E, 0x47}, {0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82}, 100, 30'000'000},
    
    // GIF87a / GIF89a
    {"gif", {0x47, 0x49, 0x46, 0x38, 0x37, 0x61}, {0x3B}, 100, 10'000'000},
    {"gif", {0x47, 0x49, 0x46, 0x38, 0x39, 0x61}, {0x3B}, 100, 10'000'000},

    // MP3 - ID3 tag
    {"mp3", {0x49, 0x44, 0x33}, {}, 100, 50'000'000},

    // MP3 - MPEG audio header (MPEG-1 Layer III)
    {"mp3", {0xFF, 0xFB}, {}, 100, 50'000'000},

    // MP4 - ftypisom or ftypmp42
    {"mp4", {0x66, 0x74, 0x79, 0x70, 0x69, 0x73, 0x6F, 0x6D}, {}, 100, 500'000'000},
    {"mp4", {0x66, 0x74, 0x79, 0x70, 0x6D, 0x70, 0x34, 0x32}, {}, 100, 500'000'000},

    // DOCX (ZIP-based format)
    {"docx", {0x50, 0x4B, 0x03, 0x04}, {}, 100, 100'000'000},

    // ZIP
    {"zip", {0x50, 0x4B, 0x03, 0x04}, {}, 100, 500'000'000}
};

// Set of allowed extensions
const unordered_set<string> ALLOWED_EXTENSIONS = {
    "pdf", "jpg", "png", "gif", "mp3", "mp4", "docx", "zip"
};

bool is_valid_drive(const string& path) {
#ifdef _WIN32
    return path.find(R"(\\.\)") == 0;
#else
    return path.find("/dev/") == 0;
#endif
}

void verify_drive_access(const string& drive_path) {
#ifdef _WIN32
    HANDLE hDrive = CreateFileA(
        drive_path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hDrive == INVALID_HANDLE_VALUE) {
        cerr << "CreateFile failed: " << GetLastError() << "\n";
        return;
    }

    ULARGE_INTEGER drive_size;
    if (!GetDiskFreeSpaceExA(drive_path.c_str(), NULL, &drive_size, NULL)) {
        cerr << "GetDiskFreeSpaceEx failed: " << GetLastError() << "\n";
        CloseHandle(hDrive);
        return;
    }

    cout << "=== Drive Verification ===\n";
    cout << "Drive size: " << drive_size.QuadPart << " bytes ("
        << drive_size.QuadPart / (1024 * 1024) << " MB)\n";

    BYTE sector[512];
    DWORD bytesRead;
    if (!ReadFile(hDrive, sector, sizeof(sector), &bytesRead, NULL)) {
        cerr << "Read failed: " << GetLastError() << "\n";
    } else {
        cout << "First 32 bytes: ";
        for (int i = 0; i < 32; ++i) {
            cout << hex << setw(2) << setfill('0')
                << static_cast<int>(sector[i]) << " ";
        }
        cout << "\n";
    }

    CloseHandle(hDrive);
#else
    struct stat st;
    if (stat(drive_path.c_str(), &st) == -1) {
        cerr << "stat failed: " << strerror(errno) << "\n";
        return;
    }

    cout << "=== Drive Verification ===\n";
    cout << "Drive size: " << st.st_size << " bytes\n";

    int fd = open(drive_path.c_str(), O_RDONLY);
    if (fd == -1) {
        cerr << "open failed: " << strerror(errno) << "\n";
        return;
    }

    unsigned char sector[512];
    if (read(fd, sector, sizeof(sector)) != sizeof(sector)) {
        cerr << "read failed: " << strerror(errno) << "\n";
    } else {
        cout << "First 32 bytes: ";
        for (int i = 0; i < 32; ++i) {
            cout << hex << setw(2) << setfill('0')
                << static_cast<int>(sector[i]) << " ";
        }
        cout << "\n";
    }
    close(fd);
#endif
}

bool match_sequence(const unsigned char* data, size_t length, const vector<unsigned char>& seq) {
    if (seq.empty() || length < seq.size()) return false;
    return memcmp(data, seq.data(), seq.size()) == 0;
}

void recover_files(const string& drive_path, const string& output_dir) {
    cout << "WARNING: This program requires administrator/root privileges to work properly.\n";
    cout << "If you encounter errors, please run as administrator/root.\n\n";

    if (!is_valid_drive(drive_path)) {
        cerr << "Error: Invalid drive path. ";
#ifdef _WIN32
        cerr << "Use format: \\.\\PhysicalDriveX\n";
#else
        cerr << "Use format: /dev/sdX\n";
#endif
        return;
    }

    verify_drive_access(drive_path);

    error_code ec;
    if (fs::exists(output_dir, ec)) {
        fs::remove_all(output_dir, ec);
    }
    if (!fs::create_directory(output_dir, ec) || ec) {
        cerr << "Error: Could not create output directory: " << ec.message() << "\n";
        return;
    }

#ifdef _WIN32
    HANDLE hDrive = CreateFileA(
        drive_path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN,
        NULL
    );

    if (hDrive == INVALID_HANDLE_VALUE) {
        cerr << "CreateFile failed: " << GetLastError() << "\n";
        return;
    }
#else
    int fd = open(drive_path.c_str(), O_RDONLY);
    if (fd == -1) {
        cerr << "open failed: " << strerror(errno) << "\n";
        return;
    }
#endif

    const size_t BUFFER_SIZE = 4 * 1024 * 1024;
    auto buffer = make_unique<unsigned char[]>(BUFFER_SIZE);
    size_t file_count = 0;
    ofstream logfile(output_dir + "/recovery_log.txt");
    auto start_time = chrono::steady_clock::now();
    size_t total_bytes_scanned = 0;

    cout << "\n=== Starting Recovery ===\n";
    cout << "Only recovering files with these extensions: ";
    for (const auto& ext : ALLOWED_EXTENSIONS) {
        cout << ext << " ";
    }
    cout << "\n";

    while (true) {
#ifdef _WIN32
        DWORD bytesRead;
        if (!ReadFile(hDrive, buffer.get(), BUFFER_SIZE, &bytesRead, NULL)) {
            cerr << "Read failed: " << GetLastError() << "\n";
            break;
        }
        if (bytesRead == 0) break;
#else
        ssize_t bytesRead = read(fd, buffer.get(), BUFFER_SIZE);
        if (bytesRead == -1) {
            cerr << "read failed: " << strerror(errno) << "\n";
            break;
        }
        if (bytesRead == 0) break;
#endif

        total_bytes_scanned += bytesRead;

        for (size_t i = 0; i < static_cast<size_t>(bytesRead); ++i) {
            for (const auto& sig : SIGNATURES) {
                // Skip if this extension isn't in our allowed list
                if (ALLOWED_EXTENSIONS.find(sig.extension) == ALLOWED_EXTENSIONS.end()) {
                    continue;
                }

                if (i + sig.header.size() > static_cast<size_t>(bytesRead)) continue;

                if (match_sequence(buffer.get() + i, bytesRead - i, sig.header)) {
                    string filename = output_dir + "/file_" + to_string(file_count) + "." + sig.extension;

                    ofstream outfile(filename, ios::binary);
                    size_t j = i;
                    size_t max_offset = i + min<size_t>(sig.max_size, static_cast<size_t>(bytesRead) - i);
                    bool found_footer = false;

                    while (j < max_offset) {
                        size_t remaining = static_cast<size_t>(bytesRead) - j;
                        size_t chunk_size = min<size_t>(remaining, 512);
                        outfile.write(reinterpret_cast<const char*>(buffer.get() + j), chunk_size);

                        if (!sig.footer.empty() && match_sequence(buffer.get() + j, remaining, sig.footer)) {
                            found_footer = true;
                            break;
                        }
                        j += chunk_size;
                    }
                    outfile.close();

                    // Verify the file has one of our allowed extensions
                    if (ALLOWED_EXTENSIONS.find(sig.extension) != ALLOWED_EXTENSIONS.end()) {
                        logfile << "Recovered: " << filename << "\n";
                        cout << "\nRecovered: " << filename << "\n";
                        file_count++;
                    } else {
                        // Delete the file if it's not in our allowed extensions
                        fs::remove(filename, ec);
                    }
                }
            }
        }

        auto now = chrono::steady_clock::now();
        double elapsed_sec = chrono::duration<double>(now - start_time).count();
        double mb_scanned = total_bytes_scanned / (1024.0 * 1024.0);
        double speed = mb_scanned / elapsed_sec;

        cout << "\rScanned: " << fixed << setprecision(1)
            << mb_scanned << " MB (" << speed << " MB/s) - "
            << file_count << " files found" << flush;
    }

#ifdef _WIN32
    CloseHandle(hDrive);
#else
    close(fd);
#endif

    auto end_time = chrono::steady_clock::now();
    double total_sec = chrono::duration<double>(end_time - start_time).count();

    cout << "\n\n=== Recovery Complete ===\n";
    cout << "Scanned " << total_bytes_scanned / (1024 * 1024) << " MB in "
        << total_sec << " seconds\n";
    cout << "Average speed: " << (total_bytes_scanned / (1024.0 * 1024.0)) / total_sec
        << " MB/s\n";
    cout << "Total files recovered: " << file_count << "\n";
    cout << "Output directory: " << fs::absolute(output_dir) << "\n";

    logfile << "Recovery completed. Total files recovered: " << file_count << "\n";
    logfile.close();
}

int main() {
    cout << "=== File Recovery Tool ===\n";
    cout << "Supported file types: ";
    for (const auto& ext : ALLOWED_EXTENSIONS) {
        cout << ext << " ";
    }
    cout << "\n";
    cout << "WARNING: This program requires administrator/root privileges for direct drive access\n\n";

#ifndef _WIN32
    cout << "Note: On Linux, you may need to run this with sudo\n";
#endif

#ifdef _WIN32
    cout << "Enter drive path (e.g., \\\\.\\PhysicalDrive1): ";
#else
    cout << "Enter drive path (e.g., /dev/sdb): ";
#endif

    string drive_path;
    getline(cin, drive_path);

    cout << "Enter output directory (default: recovered_files): ";
    string output_dir;
    getline(cin, output_dir);
    if (output_dir.empty()) {
        output_dir = "recovered_files";
    }

    recover_files(drive_path, output_dir);
    return 0;
}