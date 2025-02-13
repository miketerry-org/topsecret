// all.test.js

"use strict";

// load all required packages
const fs = require("fs");
const TopSecret = require("../index.js");

// filenames used in all tests
const loremFilename = "test/lorem.txt";
const encryptedFilename = "test/encrypted.txt";
const decryptedFilename = "test/decrypted.txt";

test("randomKey", () => {
  const topSecret = new TopSecret();
  const key = topSecret.randomKey;
  expect(key).toHaveLength(64);
});

test("encryptBuffer/decryptBuffer", () => {
  const topSecret = new TopSecret();
  topSecret.key = topSecret.randomKey;
  let lorem = fs.readFileSync(loremFilename, "utf-8");
  let encrypted = topSecret.encryptBuffer(lorem);
  let decrypted = topSecret.decryptBuffer(encrypted);
  expect(lorem).toStrictEqual(decrypted);
});

test("encryptJSON/decryptJSON", () => {
  const user1 = {
    firstname: "Donald",
    lastname: "Duck",
    email: "donald.duck@disney.com",
  };
  const topSecret = new TopSecret();
  topSecret.key = topSecret.randomKey;
  const encrypted = topSecret.encryptJSON(user1);
  const user2 = topSecret.decryptJSON(encrypted);
  expect(user1).toStrictEqual(user2);
});

test("encryptFile/decryptFile", () => {
  const topSecret = new TopSecret();
  topSecret.key = topSecret.randomKey;
  topSecret.encryptFile(loremFilename, encryptedFilename);
  topSecret.decryptFile(encryptedFilename, decryptedFilename);
  const text1 = fs.readFileSync(loremFilename, "utf-8");
  const text2 = fs.readFileSync(decryptedFilename, "utf-8");
  expect(text1).toStrictEqual(text2);
});

test("encryptJSONToFile/decryptJSONFromFile", () => {
  const user1 = {
    firstname: "Donald",
    lastname: "Duck",
    email: "donald.duck@disney.com",
  };
  const topsecret = new TopSecret();
  topsecret.key = topsecret.randomKey;
  topsecret.encryptJSONToFile(user1, "test/user.txt");
  const user2 = topsecret.decryptJSONFromFile("test/user.txt");
  expect(user1).toStrictEqual(user2);
});
