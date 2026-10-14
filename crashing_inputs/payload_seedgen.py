# Sample script to generate structured binary seeds

payload_data_1 = b"% "
payload_data_2 = b"Sa"

with open("payload_crash_03.bin", "wb") as f: 
	f.write(payload_data_1 + payload_data_2)
