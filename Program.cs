using System.Text;
using System.Security.Cryptography;

Console.WriteLine("Hello, welcome to encryption, decryption, data hashing and data masking. Let's secure some data!");
// Get data from user that needs to be encrypted
Console.Write("Enter user data you'd like to encrypt: ");
var originalData = Console.ReadLine() ?? "default data"; //set data to 'default data' if user does not enter data
// Get secret key from user used to encrypt data
Console.Write("Enter secret key used to encrypt data. Key must be 16, 24 or 32 characters long: ");
var secretKey = Console.ReadLine() ?? "asdfghjklzxcvbnmqwertyuiop123456"; //set key to 'asdfghjklzxcvbnmqwertyuiop123456' if user does not enter data

// Make sure secret key length meets GetBytes() criteria, if not randomly generate secret key
if (secretKey.Length != 16 && secretKey.Length != 24 && secretKey.Length != 32)
{
	var randomSecretKey = "";
	var rndKey = new Random();
	for (int i = 0; i < 10; i++)
	{
		randomSecretKey += Convert.ToChar(rndKey.Next(0, 26) + 65); // Generate & convert 10 random numbers to letters then append to secret key
	}
	for (int i = 0; i < 6; i++)
	{
		randomSecretKey += rndKey.Next(0, 10); // Now append 6 random numbers to secret key
	}
	secretKey = randomSecretKey;
}

// Call EncryptData() and display the data
var encryptedData = EncryptData(originalData, secretKey);
Console.WriteLine("User data encrypted: " + encryptedData);
// Call DecryptData() and display the data and secret key
var decryptedData = DecryptData(encryptedData, secretKey);
Console.WriteLine("User data decrypted: " + decryptedData);
Console.WriteLine("Secret key used to encrypt and decrypt data: " + secretKey);

// Get shared private key and password used to hash data
Console.WriteLine("Now, let's hash a password...");
Console.Write("Enter shared private key used to hash data: ");
var key = Console.ReadLine() ?? "default private key"; //set key to 'default private key' if user does not enter data
Console.Write("Enter password used to hash data: ");
var password = Console.ReadLine() ?? "default password"; //set password to 'default password' if user does not enter data
// Call ComputePasswordHash() => will display password, private key and password hash
ComputePasswordHash(key, password);

// Randomly generate then mask phone number
Console.WriteLine("For the data masking example, allow me to do the heavy lifting.");
Console.WriteLine("First, let's will randomly generate a 10-digit number used to represent a phone number.");
Console.WriteLine("Then, the number will be masked and displayed showing the first and last digits only.");
string phoneNumber = "";
var rndNumber = new Random();
for (int i = 0; i < 10; i++)
{
	phoneNumber += rndNumber.Next(0, 10); // Append 10 random number between 0 - 9
}
Console.WriteLine("The number is: " + phoneNumber);
// Call MaskNumber() => will display masked number
MaskNumber(phoneNumber);

// Program functions
string EncryptData(string data, string userKey)
{
	var textBytes = Encoding.UTF8.GetBytes(data);
	using (var aes = Aes.Create())
	{
		aes.Key = Encoding.UTF8.GetBytes(userKey);
		aes.GenerateIV();

		using (var memStream = new MemoryStream())
		{
			memStream.Write(aes.IV, 0, aes.IV.Length);
			using (var cs = new CryptoStream(memStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
			{
				cs.Write(textBytes, 0, textBytes.Length);
				cs.FlushFinalBlock();

				return Convert.ToBase64String(memStream.ToArray());
			}
		}
	}
}

string DecryptData(string encryptedText, string userKey)
{
	var textBytes = Convert.FromBase64String(encryptedText);
	using (var aes = Aes.Create())
	{
		aes.Key = Encoding.UTF8.GetBytes(userKey);
		using (var memStream = new MemoryStream(textBytes))
		{
			var iv = new byte[aes.BlockSize / 8];
			memStream.Read(iv, 0, iv.Length);
			aes.IV = iv;
			using (var cs = new CryptoStream(memStream, aes.CreateDecryptor(), CryptoStreamMode.Read))
			{
				using (var sr = new StreamReader(cs))
				{
					return sr.ReadToEnd();
				}
			}
		}
	}
}

void ComputePasswordHash(string privateKey, string password)
{
	// Generate private key bytes from users' shared private key
	var pkb = Encoding.UTF8.GetBytes(privateKey);
	// Generate password bytes from user's password
	var pb = Encoding.UTF8.GetBytes(password);
	// Compute the hash of the password using the private key
	using (var hms = new HMACSHA256(pkb))
	{
		var passwordHash = hms.ComputeHash(pb);
		Console.WriteLine("Password: " + password);
		Console.WriteLine("Private key: " + privateKey);
		Console.WriteLine("Password hash: " + BitConverter.ToString(passwordHash).Replace("-", "").ToLower());
	}
}

void MaskNumber(string phoneNumber)
{
	var numberLength = phoneNumber.Length;
	var maskedPhoneNumber = phoneNumber.Substring(0, 1) + new string('*', numberLength - 2) + phoneNumber.Substring(numberLength - 1, 1);
	Console.WriteLine("The masked number is: " + maskedPhoneNumber);
}
