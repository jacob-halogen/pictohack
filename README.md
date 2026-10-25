# pictohack

Pictochat for Linux!

Although it only works one way - from DS to Linux

## Files

`ambassador.ino`

Firmware file that powers the ESP32

`foreign_office.py`

Takes in packet bytes from ESP32, formats and builds the final output

`press_conference.py`

Displays the bytes into image format from the sent packets

## What works

- Receiving of image/text from Pictochat on DS devices
- Displaying of both black and rainbow coloured pens
- Notification of new people joining room (only after initial pair exist)

## What doesn't work

- Sometimes will miss a message because of packets getting dropped and transmissions being cut off
- Message sending back from Linux
- Displaying messages outside of terminal