# 🚀 Pipex - The Enhanced Network Utility

Pipex is a powerful Python-based networking tool that extends the capabilities of traditional tools like Netcat. It supports interactive shells, one-shot command execution, file uploads, and SSL/TLS encryption—all in one versatile utility.

## ✨ Features

🔹 **Interactive Shell** – Spawn a fully functional shell over a network connection.  
🔹 **Command Execution** – Execute commands remotely in one-shot mode.  
🔹 **File Upload** – Transfer files seamlessly between systems.  
🔹 **SSL/TLS Encryption** – Secure your connections with built-in SSL/TLS support.  
🔹 **Netcat Compatibility** – Communicates with standard `nc` clients and servers.  

---

## 📥 Installation

1️⃣ **Clone the Repository:**

```bash
git clone https://github.com/Dynamo2k1/Pipex-Swiss-Army.git
cd Pipex
```

2️⃣ **Install Dependencies:**

```bash
pip install colorama
```

3️⃣ **Make the Script Executable (Optional):**

```bash
chmod +x Pipex.py
```

---

## 🎯 Usage

Pipex offers multiple operational modes for different use cases.

### 🔹 Interactive Shell Mode

📌 **Start Pipex as a Listener (Server Mode):**

```bash
./Pipex.py -l -p 4444 -c
```

📌 **Connect as a Client:**

```bash
./Pipex.py -t 127.0.0.1 -p 4444
```

📌 **Using Netcat as a Client:**

```bash
nc 127.0.0.1 4444
```

---

### 🔹 One-Shot Command Execution

📌 **Server (Execute a Command):**

```bash
./Pipex.py -l -p 4444 -e "uname -a"
```

📌 **Client (Retrieve Command Output):**

```bash
./Pipex.py -t 127.0.0.1 -p 4444
```

---

### 🔹 File Upload Mode 📁

📌 **Server (Receive Files):**

```bash
./Pipex.py -l -p 4444 -u /tmp/uploads
```

📌 **Client (Upload a File):**

```bash
echo -e "example.txt\nThis is the file content." | ./Pipex.py -t 127.0.0.1 -p 4444 -u /tmp/uploads
```

---

### 🔹 Secure Mode (SSL/TLS) 🔐

📌 **Server (SSL Mode):**

```bash
./Pipex.py -l -p 4444 --ssl --cert mycert.pem --key mykey.pem -c
```

📌 **Client (SSL Mode):**

```bash
./Pipex.py -t 127.0.0.1 -p 4444 --ssl --cert mycert.pem --key mykey.pem
```

---

## 🔧 Dependencies

- Python 3.x ✅  
- `colorama` 📦  
- Standard Python Libraries (`sys`, `socket`, `argparse`, `threading`, `subprocess`, `ssl`, `select`, `logging`, `pathlib`, `typing`, `os`) 📜  

---

## 📜 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for more details.

---

## 🙌 Acknowledgements

🚀 Inspired by traditional networking tools like Netcat.  
❤️ Special thanks to the open-source community for invaluable resources and support!  

---

🔥 **Pipex – Your Ultimate Networking Companion!** 🔥

