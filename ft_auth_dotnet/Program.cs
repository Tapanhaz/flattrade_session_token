using System;
using System.Runtime.InteropServices;

class Program
{
    [DllImport("./ft_session_token.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr get_session_token(
        IntPtr user,
        IntPtr password,
        IntPtr totp_key,
        IntPtr api_key,
        IntPtr api_secret,
        sbyte verbose 
    );

    static void Main()
    {
        string user = "Paste userid here";
        string password = "Paste password here";
        string totpKey = "Paste totp-key here";
        string apiKey = "Paste api-key here";
        string apiSecret = "Paste api-secret here";
	sbyte verbose = 0; // 1=> verbose_mode = true, 0 => verbose_mode false

        // Allocate unmanaged memory for the strings
        IntPtr userPtr = Marshal.StringToHGlobalAnsi(user);
        IntPtr passwordPtr = Marshal.StringToHGlobalAnsi(password);
        IntPtr totpKeyPtr = Marshal.StringToHGlobalAnsi(totpKey);
        IntPtr apiKeyPtr = Marshal.StringToHGlobalAnsi(apiKey);
        IntPtr apiSecretPtr = Marshal.StringToHGlobalAnsi(apiSecret);

        IntPtr result = get_session_token(userPtr, passwordPtr, totpKeyPtr, apiKeyPtr, apiSecretPtr, verbose);

        // Free unmanaged memory
        Marshal.FreeHGlobal(userPtr);
        Marshal.FreeHGlobal(passwordPtr);
        Marshal.FreeHGlobal(totpKeyPtr);
        Marshal.FreeHGlobal(apiKeyPtr);
        Marshal.FreeHGlobal(apiSecretPtr);

        // Convert result back to managed string
        string token = Marshal.PtrToStringAnsi(result);
        Console.WriteLine("Received token: " + token);
    }
}
