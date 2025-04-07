# Advanced RAR Password Cracker Pro

![Python](https://img.shields.io/badge/Python-3.6+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey.svg)

A powerful GUI application for recovering lost passwords of RAR archives using dictionary attacks and brute force methods with multi-threading support.

## Features

- **Two Attack Modes**:
  - Dictionary attack (using wordlists)
  - Brute force attack (custom character sets)
  
- **Batch Processing**: Test multiple RAR files sequentially
- **Multi-threading**: Utilize multiple CPU cores for faster cracking
- **Progress Tracking**: Save and resume sessions
- **Drag & Drop**: Easy file input
- **Cross-platform**: Works on Windows and Linux
- **User-friendly Interface**: Real-time progress updates and statistics

## Requirements

- Python 3.6+
- Tkinter (usually included with Python)
- UnRAR executable (included in WinRAR installation on Windows)
- Additional packages: `tkinterdnd2`, `winsound` (Windows only)

## Use via exe
- Download the latest exe file and open it.
- Done
- (If any warning appear, please just ignore. It's for first time. No need to any warry. If you have any doubt you can scan or remain turn on your antivirus protection)

## Installation

1. Clone the repository or download the release package:
   ```
   https://github.com/IamAshrafee/RarPassword_Cracker.git
   cd RarPassword_Cracker
   ```

2. Install required dependencies:
   ```
   pip install -r requirements.txt
   ```

3. For Windows users, ensure WinRAR is installed (for unrar.exe)

## Usage

1. Run the application:
   ```
   python RarCracker.py
   ```

2. Select your RAR file
3. Choose attack mode (Dictionary or Brute Force)
4. Configure settings (threads, character sets for brute force, etc.)
5. Click "Start" to begin the cracking process

## Screenshots

![image](https://github.com/user-attachments/assets/28dca182-8788-44ba-aefc-07c78697fe78)

*Main application interface showing dictionary attack mode*

![image](https://github.com/user-attachments/assets/2c91a5c5-5fe6-40d3-b60f-20be16422a6e)

*Brute force configuration options*

## About

The Advanced RAR Password Cracker Pro is designed to help users recover lost passwords for RAR archives. It implements efficient password testing algorithms with multi-threading support to maximize performance. The application features a clean, intuitive interface while providing powerful functionality for both casual users and security professionals.

Key technical aspects:
- Multi-threaded password testing
- Support for both dictionary and brute force attacks
- Progress tracking and resume functionality
- Cross-platform compatibility
- Estimated time remaining calculations

## Disclaimer

This tool is intended for legal use only, such as recovering passwords from your own archives that you've legitimately forgotten. The developer is not responsible for any misuse of this software.

## License

MIT License - See [LICENSE](LICENSE) file for details

## Support

For questions or support, contact:
- Email: dev.ashrafee@gmail.com
- WhatsApp: +8801612381085
- LinkedIn: [Abdullah Al Ashrafee](https://www.linkedin.com/in/abdullahalashrafee/)

---
