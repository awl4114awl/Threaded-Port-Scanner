# Threaded Port Scanner

This is a Python-based threaded port scanner with a dark mode GUI built using Tkinter. The application allows users to scan specified ports on a target IP address using multiple threads, enhancing scan speed. It also includes features such as IP validation, error handling, logging, and the ability to save scan results in various formats (TXT, CSV). 

## Features

- **Multithreaded Scanning:** Perform port scanning using multiple threads for faster results.
- **IP Address Validation:** Ensures that the entered IP address is valid before scanning.
- **Customizable Scanning Options:**
  - Specify the number of threads to use for scanning.
  - Set custom timeout values for each port scan.
  - Choose between TCP and UDP protocols.
- **Detailed Logging:** Logs all scanning activities, including start/stop times, IPs, ports scanned, and results.
- **Error Handling:** Catches and handles various errors, such as invalid IPs, network issues, and timeouts.
- **Save and Export Results:** Save scan results in TXT or CSV format for later analysis.
- **Historical Scan Comparison:** Placeholder feature to compare results from different scans.
- **User-Friendly Interface:** Dark mode UI with tooltips for user guidance.
- **Non-Resizable Window:** Fixed window size for consistent user experience.
- **About/Help Section:** Provides information about the application and how to use it.

## Installation

### Prerequisites

- Python 3.x
- `tkinter` (usually included with Python)
- `logging`, `csv` (standard Python libraries)

### Clone the Repository

To clone the repository, use the following command:

```bash
git clone https://github.com/yourusername/threaded-port-scanner.git
cd threaded-port-scanner
```

### Run the Application

You can run the port scanner directly from the command line:

```bash
python port_scanner.py
```

## Usage

### Main Features

1. **Target IP**: Enter the IP address of the target you want to scan.
2. **Ports to Scan**: Specify the ports to scan, separated by commas (e.g., `80,443,8080`).
3. **Timeout (seconds)**: Set the timeout period for each port scan.
4. **Protocol**: Choose between TCP and UDP protocols for scanning.
5. **Number of Threads**: Define how many threads to use for the scan.
6. **Start Scan**: Begin the scanning process.
7. **Stop Scan**: Halt the scan in progress.
8. **Save Results**: Export the scan results as a TXT or CSV file.
9. **Compare Scans**: Placeholder for comparing historical scan results.
10. **About**: Provides information about the application.

### Example Usage

1. **Basic Scan**:
   - Enter the target IP: `192.168.1.1`
   - Enter ports to scan: `22,80,443`
   - Set timeout: `1`
   - Choose protocol: `TCP`
   - Set number of threads: `10`
   - Click **Start Scan** to begin.

2. **Save Results**:
   - After scanning, click **Save Results** to export the results.
   - Choose the format (TXT or CSV) and save the file.

3. **View Logs**:
   - Scan activities are logged in `port_scanner.log` for review.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Issues

If you encounter any issues or have questions, feel free to open an issue in the [GitHub repository](https://github.com/yourusername/threaded-port-scanner/issues).

## Acknowledgments

- **Python Community**: For providing extensive resources and libraries that made this project possible.
- **Tkinter Documentation**: For detailed documentation and examples on building GUIs with Tkinter.

## Future Enhancements

- **Historical Scan Comparison**: Implement full functionality to compare results from different scans.
- **Additional Protocols**: Support for more protocols beyond TCP and UDP.
- **Automated Scheduling**: Ability to schedule scans to run automatically at specified intervals.
- **Cross-Platform Packaging**: Package the application as a standalone executable for different operating systems.
