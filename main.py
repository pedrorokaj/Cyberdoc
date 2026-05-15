import sys
import os
import subprocess
from PySide6.QtWidgets import QApplication, QWidget, QLabel, QPushButton, QVBoxLayout, QFileDialog, QListWidget, QTableWidget, QTabWidget



app = QApplication(sys.argv)

window = QWidget()
window.setWindowTitle("Viverium")
window.resize(600, 400)

title_label = QLabel("Viverium")
status_label = QLabel("Status: System secure")
scan_button = QPushButton("Quick Scan")
custom_scan_button = QPushButton("Custom Scan")

def start_scan(scan_folder="C:/Users/pedro/Downloads"):
    result_list.clear()
    status_label.setText("Status: Scanning...")
    app.processEvents()

    suspicious_extensions = [".exe", ".bat", ".vbs"]

    found_count = 0
    scanned_count = 0

    for folder, subfolders, files in os.walk(scan_folder):
        for file in files:
            scanned_count += 1

            if file.lower().endswith(tuple(suspicious_extensions)):
                full_path = os.path.join(folder, file)
                result_list.addItem(f"Suspicios extensions: {full_path}")
                print("Suspicious file found:", full_path)
                found_count += 1

    status_label.setText(
        f"Status: Scan completed - scanned {scanned_count} files, found {found_count}"
    )
    home_scan.setText(
        f"Last scan: scanned {scanned_count} files, found {found_count}"
    )
    if found_count > 0:
       home_status.setText("Protection status: Action needed")
    else:
       home_status.setText("Protection status: System secure")

def custom_scan():
    folder = QFileDialog.getExistingDirectory(window, "Choose folder for custom scanning")

    if folder:
        start_scan(folder)
result_list = QListWidget()
def turn_on_firewall_profile(profile, label, display_name):
    result = subprocess.run([
        "netsh",
        "advfirewall",
        "set",
        profile,
        "state",
        "on"
    ])

    if result.returncode == 0:
        label.setText(f"{display_name}: Firewall is on.")
        firewall_status.setText(f"Firewall status: {display_name} enabled")
        home_firewall.setText("Firewall: Enabled")
    else:
        firewall_status.setText("Firewall status: Failed - run Viverium as administrator")

scan_button.clicked.connect(lambda: start_scan())
custom_scan_button.clicked.connect(custom_scan)
tabs = QTabWidget()

home_tab = QWidget()
scan_tab = QWidget()
firewall_tab = QWidget()
encryption_tab = QWidget()
password_tab = QWidget()

firewall_status = QLabel("Firewall & Network Protection")

domain_status = QLabel("Domain network: Firewall status unknown")
private_status = QLabel("Private network: Firewall status unknown")
public_status = QLabel("Public network: Firewall status unknown")

domain_button = QPushButton("Turn on Domain network firewall")
private_button = QPushButton("Turn on Private network firewall")
public_button = QPushButton("Turn on Public network firewall")

domain_button.clicked.connect(
    lambda: turn_on_firewall_profile("domainprofile", domain_status, "Domain network")
)

private_button.clicked.connect(
    lambda: turn_on_firewall_profile("privateprofile", private_status, "Private network")
)

public_button.clicked.connect(
    lambda: turn_on_firewall_profile("publicprofile", public_status, "Public network")
)

firewall_layout = QVBoxLayout()
firewall_layout.addWidget(firewall_status)

firewall_layout.addWidget(domain_status)
firewall_layout.addWidget(domain_button)

firewall_layout.addWidget(private_status)
firewall_layout.addWidget(private_button)

firewall_layout.addWidget(public_status)
firewall_layout.addWidget(public_button)

firewall_tab.setLayout(firewall_layout)



encryption_status = QLabel("Encryption: No files selected")
encryption_layout = QVBoxLayout()
encryption_layout.addWidget(encryption_status)
encryption_tab.setLayout(encryption_layout)

password_status = QLabel("Password manager: Locked")
password_layout = QVBoxLayout()
password_layout.addWidget(password_status)
password_tab.setLayout(password_layout)

home_status = QLabel("Protection status: System secure")
home_scan = QLabel("Last time scanned: Not yet scanned.")
home_firewall = QLabel("Firewall: Not yet set up")

home_layout = QVBoxLayout()
home_layout.addWidget(home_status)
home_layout.addWidget(home_scan)
home_layout.addWidget(home_firewall)
home_tab.setLayout(home_layout)

tabs.addTab(home_tab, "Home")
tabs.addTab(scan_tab, "scanning")
tabs.addTab(firewall_tab, "Firewall & Network protection")
tabs.addTab(encryption_tab, "File encryption")
tabs.addTab(password_tab, "Password maneger")

scan_layout = QVBoxLayout()
scan_layout.addWidget(scan_button)
scan_layout.addWidget(custom_scan_button)
scan_layout.addWidget(result_list)
scan_tab.setLayout(scan_layout)

layout = QVBoxLayout()
layout.addWidget(title_label)
layout.addWidget(status_label)
layout.addWidget(tabs)

window.setLayout(layout)
window.show()


sys.exit(app.exec())
