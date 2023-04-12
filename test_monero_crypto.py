import unittest
from monero_crypto import * 


class TestCrypto(unittest.TestCase):
# txid 102316cd0334ad7461b4078ea7399f78b59a15c9c10cd4012f498048bddd4940
	def setUp(self):
		self.recipient_spend = Key()
		self.recipient_spend.from_hex("cc09db7ffda93bc0e1ca515dc925e63e7138ddc7938dd0f1ca1a7952be0f9806")
		self.recipient_view = Key()
		self.recipient_view.from_hex("ecd28163a60fc9db8fca5f47dacfcaeefb934697ce9164b7e7b616e2fe546d02") 

		self.sender_spend = Key()
		self.sender_spend.from_hex("841bc3e1d446ba032d8bfb63ef1963ecb6439a9f6b111828eb2174f5579da202") 
		self.sender_view = Key()
		self.sender_view.from_hex("98cb764663e77463906198b80977b513f59c9f028a88e1d9366f79e0e5ec6207")

	def test_sender_pederson_commitment(self):
		extra = [ 1, 3, 0, 100, 82, 209, 89, 168, 211, 66, 73, 175, 31, 63, 88, 218, 164, 252, 148, 221, 100, 149, 242, 185, 125, 145, 175, 70, 43, 52, 224, 116, 67, 2, 9, 1, 81, 203, 78, 34, 81, 88, 140, 191]
		R = bytes(extra[1:33])
		self.assertEqual(sender_pedersen_commitment(R, self.recipient_view.private, 0 , "dfab6eb1594e0d03"), 100000000000) #0.1 XMR

	def test_calc_address(self):
		self.assertEqual(calc_address(self.sender_spend.public, self.sender_view.public), "4ANVvHw53F4ZoAdaHjnk3X2RG72XPbMhNcqmh7ceNJ526jWumE5gyCt9Nqhv4Kav23Toq67pN8JLtazJDTuiwt2tUwQfxmP")
	
	def test_calc_subaddress(self):
		self.assertEqual(calc_subaddress(self.sender_spend.public, self.sender_view.private, 1, 0), "85Po4U72oRp7A3yx9c7Gwq6CsCPtbyUVAcUsywMJ5Y47WSV32FgfMehPXhkj2euemijLVobX4ox2tLDeGJWngwP5ThEn1mg")	
		self.assertEqual(calc_subaddress(self.sender_spend.public, self.sender_view.private, 0, 1), "87G9JyU6SZYbz6A3E6b4GCAVDj52WYhmLKhBjrEwpVPjJDtQXWbhZcfFBVas9oGhT9a6SA98DZmbfAsVWjTbd9wfQUdg6HC")

	def test_check_stealth_address(self):
		# Transaction Public key from extra (R=rG) in blockchain
		extra = [ 1, 3, 0, 100, 82, 209, 89, 168, 211, 66, 73, 175, 31, 63, 88, 218, 164, 252, 148, 221, 100, 149, 242, 185, 125, 145, 175, 70, 43, 52, 224, 116, 67, 2, 9, 1, 81, 203, 78, 34, 81, 88, 140, 191]
		R = bytes(extra[1:33])
		self.assertTrue(check_stealth_address("9ba7a255bfbc07daab5c584b1feaccf7c90621efada6d65bf96d4f80085671a4", R, self.sender_view.private, self.sender_spend.public, 1))

	def test_calc_stealth_address(self):
		r = bytes.fromhex("3dda7fb681e8c8a3a7768156941dc6cadf0ad518c0db4aad7b295a7003426c0c") # random
		self.assertEqual(calc_stealth_address(r, self.recipient_view.public, self.recipient_spend.public, 0), "1d11aa29b8496d0e290ff72e80df0eaf0941c48e06ed7ec4b252f7d494870143") #recipienent
		self.assertEqual(calc_stealth_address(r, self.sender_view.public, self.sender_spend.public, 1), "9ba7a255bfbc07daab5c584b1feaccf7c90621efada6d65bf96d4f80085671a4") #respent


	def test_calc_key_image(self):
		# extra of transaction where the output was generated (txid = 7fe33f3f100654009d5c3a6347327e95e78ec5b90ea9b1efd2a1c8651c7d7f16)
		extra = [ 1, 125, 168, 189, 180, 9, 206, 179, 217, 7, 50, 24, 225, 201, 127, 10, 16, 35, 251, 149, 88, 168, 184, 217, 106, 176, 100, 79, 209, 123, 244, 155, 10, 2, 9, 1, 122, 131, 146, 88, 146, 83, 90, 58]
		R = bytes(extra[1:33])
		self.assertEqual(calc_key_image(self.sender_view.private, self.sender_spend.private , R , 1).hex(), "696a57fd41b24ddb858e927c02ad90cc564e8a65f9b9d53f40453485043da3e1")




if __name__ == '__main__':
    unittest.main()

