# Threaded Port Scanner

This project is a multi-threaded port scanner with a web-based graphical user interface (GUI) built using Python and Flask. It allows users to easily scan a range of ports on a specified host to check for open ports.

## Features
- **User-Friendly Interface**: Intuitive layout for inputting host and port range, and displaying results.
- **Multi-Threaded Scanning**: Efficiently scans ports using multiple threads.
- **Real-Time Results**: Instantly view the open ports as they are found.
- **Mobile Friendly**: Accessible and functional on mobile devices.

## File Structure
```
threaded-port-scanner/
├── caesar_cipher.py  # Contains the Caesar Cipher logic (if applicable)
├── main.py           # Contains the Flask web application and scanning logic
├── LICENSE           # License information
├── README.md         # Project details and usage instructions
├── .replit           # Replit configuration file
├── requirements.txt  # Dependencies for the project
├── static/           # Static files (CSS)
│   └── styles.css    # CSS for styling the web interface
└── templates/        # HTML templates
    └── index.html    # Main HTML template for the web interface
```

## How to Use
1. **Run the Application**: Click the "Run" button in Repl.it to start the Flask web application.
2. **Access the Web Interface**: Open the provided URL (typically `https://<your-repl-username>.<your-repl-project>.repl.co`) in your web browser.
3. **Enter Host and Port Range**: Type the host you want to scan and the port range (start and end ports).
4. **Start Scan**: Click the "Start Scan" button to see the results.
5. **View Results**: Open ports will be displayed in real-time.

## Getting Started
### Prerequisites
- Ensure you have Python installed.
- Flask should be installed (`pip install flask`).

### Running Locally
1. Clone the repository:
   ```sh
   git clone https://github.com/your-username/threaded-port-scanner.git
   ```
2. Navigate to the project directory:
   ```sh
   cd threaded-port-scanner
   ```
3. Install the required packages:
   ```sh
   pip install -r requirements.txt
   ```
4. Run the application:
   ```sh
   python main.py
   ```
5. Open your web browser and go to `http://127.0.0.1:5000`.

## Example Usage
1. **Host**: scanme.nmap.org
2. **Start Port**: 1
3. **End Port**: 1024

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
