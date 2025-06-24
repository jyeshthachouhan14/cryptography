import hashlib
import base64
import sys
from Crypto.Cipher import AES
from PyQt5 import QtWidgets, QtCore, QtGui
# Make sure eclib.py is in the same directory or accessible in the Python path
from eclib import EC, DiffieHellman

# Define data as a global variable
data = ""


class MainWindow(QtWidgets.QWidget):

    def __init__(self):
        super().__init__()

        self.setWindowTitle("Elliptic Curve Cryptography")
        self.setGeometry(0, 0, 500, 650)
        self.setMinimumSize(500, 650)
        self.center()

        self.tab_widget = QtWidgets.QTabWidget()
        tab = QtWidgets.QWidget()
        p3_vertical = QtWidgets.QVBoxLayout(tab)
        self.tab_widget.addTab(tab, "EC Diffie Hellman")

        labele1 = QtWidgets.QLabel("Elliptic Curve Equation")
        labele2 = QtWidgets.QLabel("y<sup>2</sup> = x<sup>3</sup> + ax + b (mod q)")
        labele1.setStyleSheet('font-size: 13pt')
        labele2.setStyleSheet('font-size: 12pt')
        labele1.setAlignment(QtCore.Qt.AlignCenter)
        labele2.setAlignment(QtCore.Qt.AlignCenter)

        labela = QtWidgets.QLabel("Enter value of a:")
        self.vala = QtWidgets.QTextEdit("2")
        labelb = QtWidgets.QLabel("Enter value of b:")
        self.valb = QtWidgets.QTextEdit("3")
        labelc = QtWidgets.QLabel("Enter value of q (prime):")
        self.valc = QtWidgets.QTextEdit("97")

        # --- FIX 1: Use valid private keys for the default curve ---
        # The order of the generator g=(3,6) on the curve y^2 = x^3 + 2x + 3 (mod 97) is 5.
        # The private keys MUST be less than the order.
        label_PrivA = QtWidgets.QLabel("Enter Private Key of A (must be < order of G):")
        self.apriv = QtWidgets.QTextEdit("2")  # Changed from 10
        label_PrivB = QtWidgets.QLabel("Enter Private Key of B (must be < order of G):")
        self.bpriv = QtWidgets.QTextEdit("4")  # Changed from 12

        label_result = QtWidgets.QLabel("ENCRYPTED / DECRYPTED TEXT")
        label_result.setStyleSheet('font-size: 12pt')
        self.textEdit = QtWidgets.QTextEdit()
        self.textEdit.setReadOnly(True)

        button_file = QtWidgets.QPushButton("Import File")
        button_encrypt = QtWidgets.QPushButton("Encrypt")
        button_decrypt = QtWidgets.QPushButton("Decrypt")

        button_file.clicked.connect(self.importfile)
        button_encrypt.clicked.connect(self.ecdhencrypt)
        button_decrypt.clicked.connect(self.ecdhdecrypt)

        hbox1 = QtWidgets.QHBoxLayout()
        vbox1 = QtWidgets.QVBoxLayout()
        vbox2 = QtWidgets.QVBoxLayout()

        vbox1.addWidget(labela)
        vbox1.addWidget(self.vala)
        vbox1.addWidget(label_PrivA)
        vbox1.addWidget(self.apriv)

        vbox2.addWidget(labelb)
        vbox2.addWidget(self.valb)
        vbox2.addWidget(label_PrivB)
        vbox2.addWidget(self.bpriv)

        hbox1.addLayout(vbox1)
        hbox1.addLayout(vbox2)

        p3_vertical.addWidget(labele1)
        p3_vertical.addWidget(labele2)
        p3_vertical.addLayout(hbox1)
        p3_vertical.addWidget(labelc)
        p3_vertical.addWidget(self.valc)
        p3_vertical.addWidget(button_file)
        p3_vertical.addWidget(label_result)
        p3_vertical.addWidget(self.textEdit)

        hbox_buttons = QtWidgets.QHBoxLayout()
        hbox_buttons.addWidget(button_encrypt)
        hbox_buttons.addWidget(button_decrypt)
        p3_vertical.addLayout(hbox_buttons)

        main_layout = QtWidgets.QVBoxLayout(self)
        main_layout.addWidget(self.tab_widget)
        self.setLayout(main_layout)

    def get_dh_params(self):
        A = int(self.vala.toPlainText())
        B = int(self.valb.toPlainText())
        C = int(self.valc.toPlainText())
        ec = EC(A, B, C)
        try:
            g, _ = ec.at(3)
        except ValueError as e:
            raise ValueError(f"The generator point x=3 is not valid for the curve parameters provided. Error: {e}")
        dh = DiffieHellman(ec, g)
        self.textEdit.append(f"Generator G order: {dh.n}")  # Display the order
        return dh

    def ecdhencrypt(self):
        global data
        if not data:
            self.textEdit.setText("Please import a file first.")
            return

        try:
            self.textEdit.clear()
            PrivA = int(self.apriv.toPlainText())
            PrivB = int(self.bpriv.toPlainText())
            dh = self.get_dh_params()

            bpub = dh.gen(PrivB)
            shared_secret_point = dh.secret(PrivA, bpub)
            key = hashlib.sha256(str(shared_secret_point.x).encode()).digest()

            BLOCK_SIZE = AES.block_size
            pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
            cipher = AES.new(key, AES.MODE_ECB)

            padded_data = pad(data).encode('utf-8')
            encrypted_bytes = cipher.encrypt(padded_data)
            encoded_text = base64.b64encode(encrypted_bytes)

            self.textEdit.append("\n--- ENCRYPTED ---\n" + encoded_text.decode('utf-8'))

            with open('Encrypted.txt', 'wb') as f:
                f.write(encoded_text)

        except Exception as e:
            # --- FIX 2: Display the actual error message for easier debugging ---
            self.textEdit.setText(f"An error occurred during encryption:\n\n{type(e).__name__}: {e}")

    def ecdhdecrypt(self):
        global data
        if not data:
            self.textEdit.setText("Please import an encrypted file first.")
            return

        try:
            self.textEdit.clear()
            PrivA = int(self.apriv.toPlainText())
            PrivB = int(self.bpriv.toPlainText())
            dh = self.get_dh_params()

            apub = dh.gen(PrivA)
            shared_secret_point = dh.secret(PrivB, apub)
            key = hashlib.sha256(str(shared_secret_point.x).encode()).digest()

            unpad = lambda s: s[:-s[-1]]
            cipher = AES.new(key, AES.MODE_ECB)

            decoded_data = base64.b64decode(data.encode('utf-8'))
            decrypted_bytes = cipher.decrypt(decoded_data)
            unpadded_bytes = unpad(decrypted_bytes)
            decrypted_text = unpadded_bytes.decode('utf-8')

            self.textEdit.append("\n--- DECRYPTED ---\n" + decrypted_text)

            with open('Decrypted.txt', 'w', encoding='utf-8') as f:
                f.write(decrypted_text)

        except (ValueError, IndexError, UnicodeDecodeError) as e:
            self.textEdit.setText(
                f"Decryption failed. The data may be corrupt, not Base64, or the key/parameters are incorrect.\n\nError: {e}")
        except Exception as e:
            self.textEdit.setText(f"An error occurred during decryption:\n\n{type(e).__name__}: {e}")

    def importfile(self):
        global data
        fname, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Open file', '', "All files (*.*);;Text files (*.txt)")
        if fname:
            try:
                with open(fname, 'r', encoding='utf-8', errors='ignore') as f:
                    data = f.read()
                    self.textEdit.setText(f"File '{fname}' loaded successfully.\n\n--- FILE CONTENT ---\n{data}")
            except Exception as e:
                self.textEdit.setText(f"Error reading file: {e}")

    def center(self):
        qr = self.frameGeometry()
        cp = QtWidgets.QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    frame = MainWindow()
    frame.show()
    sys.exit(app.exec_())