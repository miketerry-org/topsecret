"use strict";

// load necessary packages
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

class TopSecret {
  /**
   * Creates an instance of the TopSecret class.
   * Initializes key and password as null.
   */
  constructor() {
    this._key = null; // Will hold the key for encryption/decryption
    this._password = null; // Will hold the user-defined password
  }

  /**
   * Generates a random 256-bit key (32 bytes) for encryption.
   * @returns {Buffer} The generated 256-bit AES key.
   */
  get randomKey() {
    this._key = crypto.randomBytes(32);
    return this._key.toString("hex");
  }

  /**
   * Encrypt a buffer with the current key (256-bit AES).
   * @param {Buffer} buffer - The buffer to encrypt.
   * @returns {Buffer} The encrypted buffer, including the IV and ciphertext.
   * @throws {Error} If the key is not set.
   */
  encryptBuffer(buffer) {
    if (!this._key) {
      throw new Error("Key is not set.");
    }

    // Generate a random Initialization Vector (IV)
    const iv = crypto.randomBytes(16); // 16 bytes IV for AES-256-CBC

    // Create AES cipher with the current key and IV
    const cipher = crypto.createCipheriv("aes-256-cbc", this._key, iv);

    // Encrypt the buffer and return the IV + ciphertext as a Buffer
    let encrypted = Buffer.concat([iv, cipher.update(buffer), cipher.final()]);
    return encrypted;
  }

  /**
   * Encrypt a JSON object with the current key (256-bit AES).
   * The object is first serialized to a string and then encrypted.
   * @param {Object} data - The JSON object to encrypt.
   * @returns {string} The encrypted data, base64 encoded.
   * @throws {Error} If the key is not set.
   */
  encryptJSON(data) {
    if (!this._key) {
      throw new Error("Key is not set.");
    }

    // Convert the object to a string
    const jsonString = JSON.stringify(data);

    // Encrypt the string buffer
    const encryptedBuffer = this.encryptBuffer(Buffer.from(jsonString, "utf8"));

    // Return the base64 encoded encrypted buffer
    return encryptedBuffer.toString("base64");
  }

  /**
   * Decrypt a buffer with the current key (256-bit AES).
   * @param {Buffer} buffer - The encrypted buffer, including the IV and ciphertext.
   * @returns {Buffer} The decrypted plaintext buffer.
   * @throws {Error} If the key is not set.
   */
  decryptBuffer(buffer) {
    if (!this._key) {
      throw new Error("Key is not set.");
    }

    // Extract the IV from the first 16 bytes of the buffer
    const iv = buffer.slice(0, 16);
    const encryptedText = buffer.slice(16);

    // Create AES decipher with the current key and IV
    const decipher = crypto.createDecipheriv("aes-256-cbc", this._key, iv);

    // Decrypt the buffer and return the plaintext
    let decrypted = Buffer.concat([
      decipher.update(encryptedText),
      decipher.final(),
    ]);
    return decrypted;
  }

  /**
   * Decrypt a base64-encoded, encrypted JSON object with the current key (256-bit AES).
   * The decrypted data is then parsed as a JSON object.
   * @param {string} encryptedData - The base64-encoded encrypted JSON data.
   * @returns {Object} The decrypted JSON object.
   * @throws {Error} If the key is not set.
   */
  decryptJSON(encryptedData) {
    if (!this._key) {
      throw new Error("Key is not set.");
    }

    // Decode the base64-encoded string to a encrypted buffer
    const encryptedBuffer = Buffer.from(encryptedData, "base64");

    // Decrypt the buffer
    const decryptedBuffer = this.decryptBuffer(encryptedBuffer);

    // Convert the decrypted buffer back to a JSON object
    return JSON.parse(decryptedBuffer.toString("utf8"));
  }

  /**
   * Getter for the key.
   * @returns {Buffer} The current AES key.
   */
  get key() {
    return this._key.toString("hex");
  }

  /**
   * Setter for the key.
   * @param {Buffer} value - The 256-bit AES key to set.
   * @throws {Error} If the key is not 32 bytes long.
   */
  set key(value) {
    if (value.length !== 64) {
      throw new Error("Key must be 64 bytes long.");
    }

    this._key = value.from("hex");
  }

  /**
   * Getter for the password.
   * @returns {string|null} The current password or null.
   */
  get password() {
    return this._password;
  }

  /**
   * Setter for the password.
   * Converts the password into a 256-bit AES key using SHA-256.
   * @param {string} value - The password string to set.
   * @throws {Error} If the password is not a non-empty string.
   */
  set password(value) {
    if (typeof value !== "string" || value.length === 0) {
      throw new Error("Password must be a non-empty string.");
    }

    // Use SHA-256 to convert the password into a 256-bit key
    this._password = value;
    this._key = crypto.createHash("sha256").update(value).digest();
  }

  /**
   * Loads an encrypted buffer from a file, decrypts it, and returns it.
   * @param {string} filename - The path to the file to read from.
   * @returns {Buffer} The decrypted buffer.
   * @throws {Error} If file reading or decryption fails.
   */
  loadBufferFromFile(filename) {
    try {
      // Read the encrypted buffer from the file
      const encryptedBuffer = fs.readFileSync(filename);

      // Decrypt the buffer and return it
      return this.decryptBuffer(encryptedBuffer);
    } catch (error) {
      console.error("Failed to load buffer from file:", error);
      throw new Error("Failed to load buffer from file.");
    }
  }

  /**
   * Loads an encrypted JSON string from a file, decrypts it, and parses it.
   * @param {string} filename - The path to the file to read from.
   * @returns {Object} The decrypted JSON object.
   * @throws {Error} If file reading or decryption fails.
   */
  loadJSONFromFile(filename) {
    try {
      // Read the encrypted data from the file
      const encryptedData = fs.readFileSync(filename, "utf8");

      // Decrypt and parse the data
      return this.decryptJSON(encryptedData);
    } catch (error) {
      console.error("Failed to load JSON from file:", error);
      throw new Error("Failed to load JSON from file.");
    }
  }

  /**
   * Saves an encrypted buffer to a file.
   * @param {string} filename - The path to the file to save to.
   * @param {Buffer} buffer - The buffer to save after encryption.
   * @throws {Error} If file writing fails.
   */
  saveBufferToFile(filename, buffer) {
    try {
      // Encrypt the buffer
      const encryptedBuffer = this.encryptBuffer(buffer);

      // Write the encrypted buffer to the file
      fs.writeFileSync(filename, encryptedBuffer);
    } catch (error) {
      console.error("Failed to save buffer to file:", error);
      throw new Error("Failed to save buffer to file.");
    }
  }

  /**
   * Saves a  JSON object to an encrypted file.
   * @param {string} filename - The path to the file to save to.
   * @param {Object} data - The JSON object to save after encryption.
   * @throws {Error} If file writing fails.
   */
  saveJSONToFile(filename, data) {
    try {
      // Encrypt the JSON object
      const encryptedData = this.encryptJSON(data);

      // Write the encrypted data to the file
      fs.writeFileSync(filename, encryptedData);
    } catch (error) {
      console.error("Failed to save JSON to file:", error);
      throw new Error("Failed to save JSON to file.");
    }
  }
}

// Export TopSecret class
module.exports = TopSecret;
