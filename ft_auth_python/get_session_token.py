import ctypes

ft_session_token = ctypes.CDLL('./ft_session_token.dll')

ft_session_token.get_session_token.argtypes = [
                                            ctypes.c_char_p,  # user
                                            ctypes.c_char_p,  # password
                                            ctypes.c_char_p,  # totp_key
                                            ctypes.c_char_p,  # api_key
                                            ctypes.c_char_p,  # api_secret
                                            ctypes.c_int8     # verbose
                                        ]

ft_session_token.get_session_token.restype = ctypes.c_char_p

user = "Paste userid here" 
password = "Paste password here"
totp_key = "Paste totp key here"
api_key = "Paste api-key here"
api_secret = "Paste api-secret here"
verbose = 0  # 1=> verbose_mode = True, 0 => verbose_mode False

token = ft_session_token.get_session_token(
                                        user.encode(), 
                                        password.encode(), 
                                        totp_key.encode(), 
                                        api_key.encode(), 
                                        api_secret.encode(), 
                                        verbose
                                    )
if token:
    token =token.decode("utf-8")
    print(f"Session token :: {token}")

