import serial
import time

def get_puf_key():
    try:
        # Open the serial port (Ensure the correct port is used: /dev/ttyS0 or /dev/ttyAMA0)
        ser = serial.Serial('/dev/ttyS0', 9600, timeout=2)  
        ser.flush()  # Clear input and output buffers
        
        print("Requesting PUF Key from Arduino...")
        
        # Send the command to Arduino
        ser.write(b'GET_PUF\n')  # The command to request the PUF Key

        time.sleep(1)  # Wait a little to give Arduino time to respond
        
        # Read the response from Arduino
        if ser.in_waiting > 0:
            puf_key = ser.readline().decode('utf-8', errors='ignore').strip()
            if puf_key:
                print(f"PUF Key received: {puf_key}")
                return puf_key
            else:
                print("No valid response received from Arduino.")
                return None
        else:
            print("No data received from Arduino.")
            return None
        
    except (serial.SerialException, Exception) as e:
        print("Error occurred:", e)
        return None
    
    finally:
        # Ensure serial connection is closed after communication
        if 'ser' in locals() and ser.is_open:
            ser.close()



