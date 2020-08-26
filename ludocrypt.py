import sys, os
import tkinter as tk
from tkinter import filedialog as fd
from pycipher import Caesar, Vigenere, ADFGX, ADFGVX, Affine, Autokey, Atbash, Beaufort, Bifid, ColTrans, Foursquare, Gronsfeld, Playfair, Porta, Railfence, Rot13, SimpleSubstitution

debug = False
ciphertext = ''

#I think that calling the encryption function should look something like: encrypt(codetextBox.get("1.0",END).split("\n"), "encrypt", plaintextBox.get("1.0",END)), but if it doesn't shape up problematically, then this comment will just be left as an indicator of the original direction of development, for later.

def encrypt(keycodeLines, encryptionDirection, plaintextContents):
    for i in range(len(keycodeLines)): #Iterate over the keycode.
        if(encryptionDirection == "encrypt"):
            splitLine = keycodeLines[i].split()
        else:
            splitLine = keycodeLines[len(keycodeLines)-1-i].split() #This ensures that if the encryption direction is set to decrypt, that this for loop reads the keycode.txt from end to beginning.

        # print("Line " + str(i) + " is " + keycodeLines[i] + " and the split line is: " + str(splitLine)) # This was an old debugging line that may be useful in the future.
        if(splitLine[0] == "caesar"):
            if(int(splitLine[1]) > 25 or int(splitLine[1]) < 1):
                print("Keycode line: " + str(i + 1) + ": Caesar shift detected on keycode line " + str(i) + " attempting to shift by value " + splitLine[1] + ".")
                sys.exit()
            else:
                originalPlaintext = plaintextContents
                if(debug):
                    print("Keycode line: " + str(i + 1) + ": Caesar shift detected with an argument of " + splitLine[1] + ".")
                if(encryptionDirection == "encrypt"):
                    plaintextContents = Caesar(int(splitLine[1])).encipher(plaintextContents)
                else:
                    plaintextContents = Caesar(int(splitLine[1])).decipher(plaintextContents)
                if(debug):
                    print("Keycode line: " + str(i + 1) + ": Caesar shifted " + originalPlaintext + " by " + splitLine[1] + " with a result of " + plaintextContents + ".")
        elif(splitLine[0] == "vigenere"):
            if(type(splitLine[1] != str)):
                originalPlaintext = plaintextContents
                if(debug):
                    print("Keycode line: " + str(i + 1) + ": Vigenère shift detected with an argument of " + splitLine[1] + ".")
                if(encryptionDirection == "encrypt"):
                    plaintextContents = Vigenere(splitLine[1]).encipher(plaintextContents)
                else:
                    plaintextContents = Vigenere(splitLine[1]).decipher(plaintextContents)
                if(debug):
                    print("Keycode line: " + str(i + 1) + ": Vigenère shifted " + originalPlaintext + " by " + splitLine[1] + " with a result of " + plaintextContents + ".")
            else:
                print("Keycode line: " + str(i + 1) + ": Vigenère shift detected on keycode line " + str(i) + " attempting to use key that is not a string.")
        elif(splitLine[0] == "porta"):
            if(type(splitLine[1] != str)):
                originalPlaintext = plaintextContents
                if(debug):
                    print("Keycode line: " + str(i + 1) + ": Porta cipher detected with an argument of " + splitLine[1] + ".")
                if(encryptionDirection == "encrypt"):
                    plaintextContents = Porta(splitLine[1]).encipher(plaintextContents)
                else:
                    plaintextContents = Porta(splitLine[1]).decipher(plaintextContents)
                if(debug):
                    print("Keycode line: " + str(i + 1) + ": Vigenère shifted " + originalPlaintext + " by " + splitLine[1] + " with a result of " + plaintextContents + ".")
            else:
                print("Keycode line: " + str(i + 1) + ": Vigenère shift detected on keycode line " + str(i) + " attempting to use key that is not a string.")
        elif(splitLine[0] == "adfgx"):
            if(len(splitLine[1]) != 25): # This makes sure that the keysquare's length is exactly 25.
                print("Keycode line: " + str(i + 1) + ": ADFGX cipher detected on keycode line " + str(i) + " attempting to use keysquare that is not 25 characters long.")
                sys.exit()
            else:
                originalPlaintext = plaintextContents
                if(debug):
                    print("Keycode line: " + str(i + 1) + ": ADFGX cipher detected with a keysquare of " + splitLine[1] + " and a keyword of " + splitLine[2] + ".")
                plaintextContents = ADFGX(splitLine[1], splitLine[2]).encipher(plaintextContents)
                if(debug):
                    print("Keycode line: " + str(i + 1) + ": ADFGX ciphered " + originalPlaintext + " by a keysquare of " + splitLine[1] + " and a keyword of " + splitLine[2] + " with a result of " + plaintextContents + ".")
        elif(splitLine[0] == "adfgvx"): #The first argument is the keysquare, and the second argument is the keyword.
            if(len(splitLine[1]) != 36): # This makes sure that the keysquare's length is exactly 36.
                print("Keycode line: " + str(i) + ": ADFGVX cipher detected on keycode line " + str(i) + " attempting to use keysquare that is not 25 characters long, but is instead " + str(len(splitLine[1])) + " characters long.")
                sys.exit()
            else:
                originalPlaintext = plaintextContents
                if(debug):
                    print("Keycode line: " + str(i + 1) + ": ADFGVX cipher detected with a keysquare of " + splitLine[1] + " and a keyword of " + splitLine[2] + ".")
                plaintextContents = ADFGVX(splitLine[1], splitLine[2]).encipher(plaintextContents)
                if(debug):
                    print("Keycode line: " + str(i + 1) + ": ADFGVX ciphered " + originalPlaintext + " by a keysquare of " + splitLine[1] + " and a keyword of " + splitLine[2] + " with a result of " + plaintextContents + ".")
        elif(splitLine[0] == "affine"):
            if((int(splitLine[2]) < 1) or (int(splitLine[2]) > 25)):
                print("Keycode line: " + str(i + 1) + ": Affine cipher detected on keycode line " + str(i) + " attempting to use b value outside of the range of 1-25.")
                sys.exit()
            elif((int(splitLine[1]) == 13) or (int(splitLine[1])%2 != 1) or (int(splitLine[1]) > 25) or (int(splitLine[1]) < 1)):
                print("Keycode line: " + str(i + 1) + ": Affine cipher detected on keycode line " + str(i) + " attempting to use an a value outside of the range of 1-25, that is even, or that is 13, all of which are not permitted.")
                sys.exit()
            else:
                originalPlaintext = plaintextContents
                if(debug):
                    print("Keycode line: " + str(i + 1) + ": Affine cipher detected with an a value of " + splitLine[1] + " and a b value of " + splitLine[2] + ".")
                plaintextContents = Affine(int(splitLine[1]), int(splitLine[2])).encipher(plaintextContents)
                if(debug):
                    print("Keycode line: " + str(i + 1) + ": Affine ciphered " + originalPlaintext + " by value a " + splitLine[1] + " and value b " + splitLine[2] + " with a result of " + plaintextContents + ".")
        elif(splitLine[0] == "autokey"): #TODO: The autokey cipher actually doesn't have any requirements for the key, but will be configured to set off a ton of warnings assuming the config flags allow for it.
                originalPlaintext = plaintextContents
                if(debug):
                    print("Keycode line: " + str(i + 1) + ": Autokey cipher detected with an key of " + splitLine[1] + ".")
                plaintextContents = Autokey(splitLine[1]).encipher(plaintextContents)
                if(debug):
                    print("Keycode line: " + str(i + 1) + ": Autokey ciphered " + originalPlaintext + " by key of " + splitLine[1] + " for a result of " + plaintextContents + ".")
        elif(splitLine[0] == "atbash"):
                originalPlaintext = plaintextContents
                if(debug):
                    print("Keycode line: " + str(i + 1) + ": Autokey cipher detected.")
                plaintextContents = Affine(25, 25).encipher(plaintextContents)
                if(debug):
                    print("Keycode line: " + str(i + 1) + ": Atbash ciphered " + originalPlaintext + " for a result of " + plaintextContents + ".")
        elif(splitLine[0] == "beaufort"):
            if(type(splitLine[1] == str)):
                originalPlaintext = plaintextContents
                if(debug):
                    print("Keycode line: " + str(i + 1) + ": Beaufort shift detected with an argument of " + splitLine[1] + ".")
                plaintextContents = Beaufort(splitLine[1]).encipher(plaintextContents)
                if(debug):
                    print("Keycode line: " + str(i + 1) + ": Beaufort shifted " + originalPlaintext + " by " + splitLine[1] + " with a result of " + plaintextContents + ".")
            else:
                print("Keycode line: " + str(i + 1) + ": Beaufort shift detected on keycode line " + str(i) + " attempting to use key that is not a string.")
        elif(splitLine[0] == "bifid"):
            if(len(splitLine[1]) != 25): # This makes sure that the keysquare's length is exactly 25.
                print("Keycode line: " + str(i + 1) + ": Bifid cipher detected on keycode line " + str(i) + " attempting to use keysquare that is not 25 characters long.")
                sys.exit()
            else:
                originalPlaintext = plaintextContents
                if(debug):
                    print("Keycode line: " + str(i + 1) + ": Bifid cipher detected with a keysquare of " + splitLine[1] + " and a keyword of " + splitLine[2] + ".")
                plaintextContents = Bifid(splitLine[1], int(splitLine[2])).encipher(plaintextContents)
                if(debug):
                    print("Keycode line: " + str(i + 1) + ": Bifid ciphered " + originalPlaintext + " by a keysquare of " + splitLine[1] + " and a keyword of " + splitLine[2] + " with a result of " + plaintextContents + ".")
        elif(splitLine[0] == "coltrans"):
            if(type(splitLine[1] != str)): # Check that the encryption key is a string.
                originalPlaintext = plaintextContents
                if(debug):
                    print("Keycode line: " + str(i + 1) + ": Columnar transposition shift detected with an argument of " + splitLine[1] + ".")
                plaintextContents = ColTrans(splitLine[1]).encipher(plaintextContents)
                if(debug):
                    print("Keycode line: " + str(i + 1) + ": Columnar transposition shifted " + originalPlaintext + " by " + splitLine[1] + " with a result of " + plaintextContents + ".")
                print("Keycode line: " + str(i + 1) + ": Columnar transposition shift detected on keycode line " + str(i) + " attempting to use key that is not a string.")
        #Foursquare's giving me a strange error on the pycipher end of things. This will be commented out for now, as it's not integral to the final product getting shipped.
        # elif(splitLine[0] == "foursquare"): #If the command is calling for an ADFGX cipher. The first argument is the keysquare, and the sceond argument is the keyword.
        #     if(len(splitLine[1]) != 25): # This makes sure that the keysquare's length is exactly 25.
        #         print("Foursquare cipher detected on keycode line " + str(i) + " attempting to use keysquare that is not 25 characters long.")
        #         sys.exit()
        #     elif(len(splitLine[2]) != 25): # This makes sure that the keysquare's length is exactly 25.
        #         print("Foursquare cipher detected on keycode line " + str(i) + " attempting to use keysquare that is not 25 characters long.")
        #         sys.exit()
        #     else:
        #         originalPlaintext = plaintextContents
        #         if(debug):
        #             print("Foursquare cipher detected with a keysquare of " + splitLine[1] + " and a keyword of " + splitLine[2] + ".")
        #         plaintextContents = Foursquare(key1 = splitLine[1], key2 = splitLine[2]).encipher(plaintextContents)
        #         if(debug):
        #             print("Foursquare ciphered " + originalPlaintext + " by a keysquare of " + splitLine[1] + " and a keyword of " + splitLine[2] + " with a result of " + plaintextContents + ".")
        elif(splitLine[0] == "playfair"):
            if(len(splitLine[1]) != 25): # This makes sure that the keysquare's length is exactly 25.
                print("Keycode line: " + str(i + 1) + ": Playfair cipher detected on keycode line " + str(i) + " attempting to use keysquare that is not 25 characters long.")
                sys.exit()
            else:
                originalPlaintext = plaintextContents
                if(debug):
                    print("Keycode line: " + str(i + 1) + ": Playfair cipher detected with a keysquare of " + splitLine[1] + ".")
                    plaintextContents = Playfair(splitLine[1]).encipher(plaintextContents)
                if(debug):
                    print("Keycode line: " + str(i + 1) + ": Playfair ciphered " + originalPlaintext + " by a keysquare of " + splitLine[1] + " with a result of " + plaintextContents + ".")
        elif(splitLine[0] == "railfence"): #TODO: Fix this so that it throws an error if the key is a bad length relative to the plaintext.
            if(splitLine[1].isdigit() == False):
                print("Keycode line: " + str(i + 1) + ": Railfence cipher detected on keycode line " + str(i) + " with a non-numerical key.")
                sys.exit()
            elif(int(splitLine[1]) < 1): # This makes sure that the keysquare's length is exactly 25.
                print("Keycode line: " + str(i + 1) + ": Railfence cipher detected on keycode line " + str(i) + " attempting to use a key less than 0.")
                sys.exit()
            else:
                originalPlaintext = plaintextContents
                if(debug):
                    print("Keycode line: " + str(i + 1) + ": Railfence cipher detected with a key of " + splitLine[1] + ".")
                    plaintextContents = Railfence(int(splitLine[1])).encipher(plaintextContents)
                if(debug):
                    print("Keycode line: " + str(i + 1) + ": Railfence ciphered " + originalPlaintext + " by a key of " + splitLine[1] + " with a result of " + plaintextContents + ".")
        elif(splitLine[0] == "rot13"):
            originalPlaintext = plaintextContents
            if(debug):
                print("Keycode line: " + str(i + 1) + ": Rot13 cipher detected.")
            if(encryptionDirection == "encrypt"):
                plaintextContents = Rot13().encipher(plaintextContents)
            else:
                plaintextContents = Rot13().decipher(plaintextContents)
            if(debug):
                print("Keycode line: " + str(i + 1) + ": Rot13 ciphered " + originalPlaintext + " with a result of " + plaintextContents + ".")
        elif(splitLine[0] == "simplesub"):
            if(len(splitLine[1]) != 26): # This makes sure that the keysquare's length is exactly 25.
                print("Keycode line: " + str(i + 1) + ": Simple substitution cipher detected on keycode line " + str(i) + " attempting to use key that is not 26 characters long.")
                sys.exit()
            else:
                originalPlaintext = plaintextContents
                if(debug):
                    print("Keycode line: " + str(i + 1) + ": Simple substitution cipher detected with a key of " + splitLine[1] + ".")
                if(encryptionDirection == "encrypt"):
                    plaintextContents = SimpleSubstitution(splitLine[1]).encipher(plaintextContents)
                else:
                    plaintextContents = SimpleSubstitution(splitLine[1]).decipher(plaintextContents)
                if(debug):
                    print("Keycode line: " + str(i + 1) + ": Simple substitution ciphered " + originalPlaintext + " by a key of " + splitLine[1] + " with a result of " + plaintextContents + ".")
    if(i == (len(keycodeLines) - 1)):
        # print(plaintextContents) #A debug catch that you may find useful later.
        return plaintextContents



tkRoot = tk.Tk()
tkRoot.geometry("800x355")

titleLabel = tk.Label(tkRoot, text="LudoCrypt")
titleLabel.config(font=("Courier", 44))
tkRoot.update() # This is so that titleLabel.winfo_width() will return the correct value.
# print('Returned window width is ', tkRoot.winfo_screenwidth()) #Used this for debugging at the time of creating the GUI, could still be helpful later.
titleLabel.place(x=(tkRoot.winfo_screenwidth() / 6) - (titleLabel.winfo_width() / 2) + 30, y=10) #TODO: Properly center this title. Hacked it together for the time being, although it seems to be working pretty well as it is, so I'll leave it as it is until something shows an issue.

plaintextLabel = tk.Label(tkRoot, text="Plaintext:")
plaintextLabel.config(font=("Courier", 12))
plaintextLabel.place(x=18, y=80) #TODO: Seems too static, but we'll see if it ever causes issues, which I doubt it will honestly.

plaintextBox = tk.Text(tkRoot, height=12, width=35)
plaintextBox.place(x=20, y=100)
plaintextBox.insert(tk.END, "Plaintext filler text.")

codetextLabel = tk.Label(tkRoot, text="Codetext:")
codetextLabel.config(font=("Courier", 12))
codetextLabel.place(x=499, y=80) #TODO: This too seems too static, but we'll see if it ever causes issues, which I doubt it will honestly.

codetextBox = tk.Text(tkRoot, height=12, width=35)
codetextBox.place(x=500, y=100)
codetextBox.insert(tk.END, "Codetext filler text.")

def encryptTextCallback():
    ciphertextBox.delete(0, tk.END) # This clears the box, so that the encrypted text does not stack upon what was last there.
    encryptedTextToPlace = encrypt(codetextBox.get("1.0","end-1c").split("\n"), "encrypt", plaintextBox.get("1.0","end-1c"))
    ciphertextBox.insert(tk.END, encryptedTextToPlace)
encryptButton = tk.Button(tkRoot, text="Encrypt", command=encryptTextCallback)
encryptButton.place(x=400, y=100)

def decryptTextCallback():
    decryptedTextToPlace = encrypt(codetextBox.get("1.0","end-1c").split("\n"), "decrypt", plaintextBox.get("1.0","end-1c"))
    ciphertextBox.insert(tk.END, decryptedTextToPlace)
decryptButton = tk.Button(tkRoot, text="Decrypt", command=decryptTextCallback)
decryptButton.place(x=350, y=100)

def loadPlaintextCallback():
    plaintextFilename = fd.askopenfilename(initialdir=os.getcwd(), title="Select Plaintext File", filetypes=(("Txt files","*.txt"),("All files","*.*")))
    plaintextFile = open(plaintextFilename, "r")
    plaintextBox.delete(1.0, tk.END)
    plaintextBox.insert(tk.END, plaintextFile.read())
    plaintextFile.close()
loadPlaintextButton = tk.Button(tkRoot, text="Load Plaintext", command=loadPlaintextCallback)
loadPlaintextButton.place(x=357, y=130)

def savePlaintextCallback():
    plaintextFileToWrite = fd.asksaveasfile(defaultextension='.txt', filetypes=[("Txt file", "*.txt")])
    plaintextFileToWrite.write(plaintextBox.get("1.0","end-1c"))
    plaintextFileToWrite.close()
savePlaintextButton = tk.Button(tkRoot, text="Save Plaintext", command=savePlaintextCallback)
savePlaintextButton.place(x=357, y=160)

def loadCodetextCallback():
    codetextFilename = fd.askopenfilename(initialdir=os.getcwd(), title="Select Codetext File", filetypes=(("Txt files","*.txt"),("All files","*.*")))
    codetextFile = open(codetextFilename, "r")
    codetextBox.delete(1.0, tk.END)
    codetextBox.insert(tk.END, codetextFile.read())
    codetextFile.close()
loadCodetextButton = tk.Button(tkRoot, text="Load Codetext", command=loadCodetextCallback)
loadCodetextButton.place(x=355, y=190)

def saveCodetextCallback():
    codetextFileToWrite = fd.asksaveasfile(defaultextension='.txt', filetypes=[("Txt file", "*.txt")])
    codetextFileToWrite.write(codetextBox.get("1.0","end-1c"))
    codetextFileToWrite.close()
saveCodetextButton = tk.Button(tkRoot, text="Save Codetext", command=saveCodetextCallback)
saveCodetextButton.place(x=357, y=220)

def saveCiphertext():
    ciphertextFileToWrite = fd.asksaveasfile(defaultextension='.txt', filetypes=[("Txt file", "*.txt")])
    ciphertextFileToWrite.write(ciphertextBox.get())
    ciphertextFileToWrite.close()
saveCiphertextButton = tk.Button(tkRoot, text="Save Ciphertext", command=saveCiphertext)
saveCiphertextButton.place(x=352, y=250)

ciphertextLabel = tk.Label(tkRoot, text="Ciphertext:")
ciphertextLabel.config(font=("Courier", 12))
ciphertextLabel.place(x=18, y=295)

# ciphertextBox = tk.Text(tkRoot, height=1, width=95, undo=True, wrap=NONE)
ciphertext = ""
ciphertextBox = tk.Entry(tkRoot, textvariable=ciphertext, width=127)
ciphertextBox.place(x=20, y=317)
ciphertextBox.insert(tk.END, "Ciphertext output filler text here.")

creditLabel = tk.Label(tkRoot, text="Developed by Tommy Royall, ©2020")
creditLabel.config(font=("Courier", 8))
creditLabel.place(x=18, y=336)

tkRoot.mainloop()

#This was used back when it was text based, and I'm going to leave it in just in case I ever (need to OR want to) revert back to a command line interface.
# if(len(sys.argv) != 4 and len(sys.argv) != 5): # Check to make sure that the proper arguments are being provided.
#     print("Ludocrypt syntax: ludocrypt direction keycode plaintext")
#     sys.exit()
# else: #Start loading in the files.
#     if(sys.argv[1] == "encrypt" or sys.argv[1] == "decrypt"):
#         encryptionDirection = sys.argv[1]
#         if(debug):
#             print("Encryption direction is " + encryptionDirection)
#     else:
#         print("Encryption direction must be 'encrypt' or 'decrypt', syntax is 'ludocrypt direction keycode plaintext'")
#         sys.exit()
#
#     if(len(sys.argv) == 5):
#         if(sys.argv[4] == "debug"):
#             debug = True
#             print("Debug has been set to true.")
#         else:
#             debug = False
#
#     if(debug): #If debug is checked, then talk too much.
#         print("Attempting to open " + sys.argv[2] + ".")
#     try:
#         keycodeFile = open(sys.argv[2], "r")
#         keycodeContents = keycodeFile.read()
#         keycodeLines = keycodeContents.split('\n')
#     except OSError:
#         print("Error encountered opening keycode file " + sys.argv[2] + ".")
#         sys.exit()
#     if(debug): #If debug is checked, then talk too much.
#         print("Attempting to open " + sys.argv[3] + " .")
#     try:
#         plaintextFile = open(sys.argv[3], "r")
#         plaintextContents = plaintextFile.read()
#     except OSError:
#         print("Error encountered opening plaintext file " + sys.argv[3] + ".")
#         sys.exit()
#     # print("Lines in file: " + str(len(fileLines)))
