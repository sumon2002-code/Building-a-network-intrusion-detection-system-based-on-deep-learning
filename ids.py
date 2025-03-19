import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from tensorflow.keras.models import load_model
import pickle
import os
import time
import logging
import joblib
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime
import json
# Định nghĩa các cột từ plugin ml_classifiers 
COLUMN_NAMES = [
    'Timestamp','IP', 'Destination Port', 'Flow Duration', 'Total Fwd Packets',
    'Total Backward Packets', 'Total Length of Fwd Packets',
    'Total Length of Bwd Packets', 'Fwd Packet Length Max',
    'Fwd Packet Length Min', 'Fwd Packet Length Mean',
    'Fwd Packet Length Std', 'Bwd Packet Length Max',
    'Bwd Packet Length Min', 'Bwd Packet Length Mean',
    'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s',
    'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max',
    'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std',
    'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags',
    'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length',
    'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
    'Packet Length Min', 'Packet Length Max', 'Packet Length Mean',
    'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
    'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count',
    'URG Flag Count', 'CWR Flag Count', 'ECE Flag Count', 'Down/Up Ratio',
    'Average Packet Size', 'Fwd Segment Size Avg', 'Bwd Segment Size Avg', 'Fwd Header Length.1',
    'Fwd Bytes/Bulk Avg', 'Fwd Packet/Bulk Avg', 'Fwd Bulk Rate Avg',
    'Bwd Bytes/Bulk Avg', 'Bwd Packet/Bulk Avg', 'Bwd Bulk Rate Avg',
    'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets',
    'Subflow Bwd Bytes', 'Init_Win_bytes_forward',
    'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward',
    'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean',
    'Idle Std', 'Idle Max', 'Idle Min'
]



def load_and_preprocess_data():
    # Đọc file được tạo bởi plugin ml_classifiers
    file_path = '/home/hieupham/Desktop/logs/logs.txt'
    
    while not os.path.exists(file_path):
        print(f"Waiting for data in {file_path}...")
        time.sleep(10)
        
    # Đọc dữ liệu dạng space-separated values 
    data = pd.read_csv(file_path, sep=' ', names=COLUMN_NAMES)
    
    
    data = data.drop(["Fwd Header Length.1"], axis=1)

    features = data.drop(["Timestamp","IP"], axis=1)


    # Chuẩn hóa dữ liệu
    
    scaler = joblib.load('/home/hieupham/Desktop/FlaskIDS/model/scaler.pkl')
    X = scaler.transform(features)

    
    
    # Reshape data để phù hợp với input shape của model
    X = X.reshape(-1, 77, 1)
    
    return data, X

def send_alert_email(attack_data):
    from_addr = ""  # Địa chỉ email người gửi
    to_addr = ""  # Địa chỉ email người nhận
    subject = "Network Intrusion Detection Alert"
    body = "Tệp đính kèm chứa lưu lượng được dự đoán là tấn công"

    # Tạo email với tệp đính kèm
    msg = MIMEMultipart()
    msg['From'] = from_addr
    msg['To'] = to_addr
    msg['Subject'] = subject
    
    msg.attach(MIMEText(body, 'plain'))
    
    # Đính kèm file
    filename = "predicted_attack_data.csv"
    attachment = open(attack_data, "rb")
    
    part = MIMEBase('application', 'octet-stream')
    part.set_payload(attachment.read())
    encoders.encode_base64(part)
    part.add_header('Content-Disposition', f"attachment; filename= {filename}")
    
    msg.attach(part)
    
    # Gửi email qua SMTP server
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)  # Sử dụng SMTP server của Gmail
        server.starttls()  # Bảo mật kết nối
        server.login(from_addr, "")  # Đăng nhập vào email
        text = msg.as_string()
        server.sendmail(from_addr, to_addr, text)
        server.quit()
        print("Alert email sent successfully!")
        with open('/home/hieupham/Desktop/FlaskIDS/alert_status.json', 'w') as alert_file:
            json.dump({'alert': True, 'timestamp': datetime.now().isoformat(), 'file': attack_data}, alert_file)
    except Exception as e:
        print(f"Failed to send email: {str(e)}")
   


def runIDS():
    print("Starting IDS...")
    
    try:
        # Load model CNN đã train
        model = load_model("/home/hieupham/Desktop/FlaskIDS/model/lstm_model.h5")
        
        # Load và tiền xử lý dữ liệu
        data, X = load_and_preprocess_data()
        
        # Dự đoán 
        predictions = model.predict(X)
        y_pred = np.argmax(predictions, axis=1)
        # Ánh xạ nhãn
        label_mapping = {
            0: 'BENIGN', 
            1: 'Bot',
            2: 'Brute Force',
            3: 'DoS Attack',
            4: 'PortScan'   
        }

        predicted_labels = [label_mapping[label] for label in y_pred]
        
        # Print probabilities for each prediction
        # for i, probs in enumerate(predictions):
        #     print(f"Sample {i}:")
        #     for j, prob in enumerate(probs):
        #         print(f"  Class {j}: {prob:.4f}")
        
        # Thêm cột dự đoán vào dữ liệu gốc
        data['Predicted_Label'] = predicted_labels
        
        # Optionally, add probabilities to the DataFrame
        for j, label in label_mapping.items():
            data[f'Prob_{label}'] = predictions[:, j]
        

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        # Lưu kết quả
        predicted_data_filename = f"/home/hieupham/Desktop/FlaskIDS/predicted/predicted_data_{timestamp}.csv"
        data.to_csv(predicted_data_filename, index=False)

        attack_data = data[data['Predicted_Label'] != 'BENIGN']


        if not attack_data.empty:
            # Lưu các dữ liệu tấn công vào file
            predicted_attack_data_filename = f"/home/hieupham/Desktop/FlaskIDS/predicted_attack/predicted_attack_data_{timestamp}.csv"
            attack_data.to_csv(predicted_attack_data_filename, index=False)
            
            # Gửi email cảnh báo
            send_alert_email(predicted_attack_data_filename)


        
        print("Detection completed. Shutting down...")
        
    except Exception as e:
        print(f"Error occurred: {str(e)}")
        logging.error(f"Error occurred: {str(e)}")
    finally:
        print("Exiting IDS...")

if __name__ == "__main__":
    runIDS()
