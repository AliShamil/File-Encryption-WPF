using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace File_Encryption_WPF;



public partial class MainWindow : Window
{
    string ivAsBase64;
    string keyAsBase64;
    string encryptedTextAsBase64;
    int _keySize;
    private CancellationTokenSource? _cts;
    public string FilePath { get; set; } = null!;

    public MainWindow()
    {
        InitializeComponent();
        DataContext = this;
        ivAsBase64 = string.Empty;
        keyAsBase64 = string.Empty;
        encryptedTextAsBase64 = string.Empty;
        _keySize = 128;
    }
    private void Window_Loaded(object sender, RoutedEventArgs e)
       => rbtn128.IsChecked= true;


    private void btnFile_Click(object sender, RoutedEventArgs e)
    {
        FileDialog dialog = new OpenFileDialog();
        dialog.Filter = "Text files (*.txt)|*.txt";

        var result = dialog.ShowDialog();

        if (result == true)
            txtPath.Text = dialog.FileName;
    }

    private void btnStart_Click(object sender, RoutedEventArgs e)
    {
        var chararcterSize = _keySize/8;

        StringBuilder sb = new();

        if (string.IsNullOrWhiteSpace(FilePath))
        {
            MessageBox.Show("Enter File Path");
            return;
        }

        if (!File.Exists(FilePath))
            sb.Append($"'{FilePath}' was not found\n");

        if (rbtnDecrypt.IsChecked == false && rbtnEncrypt.IsChecked == false)
            sb.Append("Action(encrypt/decrypt) must be choosen!\n");

        if (string.IsNullOrWhiteSpace(txtPassword.Password))
            sb.Append("Password must be written for encryption!");

        if (txtPassword.Password.Length!=chararcterSize)
            sb.Append($"Password must contain {chararcterSize} characters");

        if (sb.Length > 0)
        {
            MessageBox.Show(sb.ToString());
            return;
        }

        progressBar.Value = 0;

        _cts = new CancellationTokenSource();

        if (rbtnEncrypt.IsChecked == true)
            EncryptAndWriteToFile(_cts.Token);
        else
            DecryptAndWriteToFile(_cts.Token);

    }

    private void txtPassword_LostFocus(object sender, RoutedEventArgs e)
    {
        var chararcterSize = _keySize/8;
        if (txtPassword.Password.Length <chararcterSize)
        {
            MessageBox.Show($"You need to write at least {chararcterSize} characters");
        }

    }

    private void rbtnKeySize_Checked(object sender, RoutedEventArgs e)
    {
        if (!string.IsNullOrEmpty(txtPassword.Password))
            txtPassword.Password = string.Empty;

        var name = (sender as RadioButton).Name;

        switch (string.Join("", name.ToCharArray().Where(Char.IsDigit)))
        {
            case "128":
                _keySize= 128;
                break;
            case "192":
                _keySize= 192;
                break;
            case "256":
                _keySize= 256;
                break;
        }
        txtPassword.MaxLength= _keySize/8;
    }


    private void EncryptAndWriteToFile(CancellationToken token)
    {
        var text = File.ReadAllText(FilePath);

        var password = txtPassword.Password;

        var bytesToWrite = Encryp(ref ivAsBase64, ref keyAsBase64, ref encryptedTextAsBase64, text, password);

        btnStart.IsEnabled = false;
        btnCancel.IsEnabled = true;

        ThreadPool.QueueUserWorkItem(o =>
        {
            using var fs = new FileStream(FilePath, FileMode.Truncate);

            for (int i = 0; i < bytesToWrite.Length; i++)
            {

                if (token.IsCancellationRequested)
                {
                    fs.Dispose();
                    Dispatcher.Invoke(() => File.WriteAllText(FilePath, text));
                    Dispatcher.Invoke(() => progressBar.Value = 0);
                    Dispatcher.Invoke(() => btnStart.IsEnabled = true);
                    return;
                }


                if (i != 0)
                    Dispatcher.Invoke(() => progressBar.Value = 100 * i / bytesToWrite.Length);

                fs.WriteByte(bytesToWrite[i]);
                Thread.Sleep(1);
            }

            fs.Seek(0, SeekOrigin.Begin);

            Dispatcher.Invoke(() => btnStart.IsEnabled = true);
            Dispatcher.Invoke(() => btnCancel.IsEnabled = false);
            Dispatcher.Invoke(() => progressBar.Value = 100);
        });
    }

    private void DecryptAndWriteToFile(CancellationToken token)
    {
        var bytes = File.ReadAllBytes(FilePath);

        var password = txtPassword.Password;

        var bytesToWrite = Decryp(ref ivAsBase64, ref keyAsBase64, ref encryptedTextAsBase64);
        var text = Encoding.UTF8.GetString(bytesToWrite); ;

        btnStart.IsEnabled = false;
        btnCancel.IsEnabled = true;

        ThreadPool.QueueUserWorkItem(o =>
        {
            using var fs = new FileStream(FilePath, FileMode.Truncate);

            for (int i = 0; i < bytesToWrite.Length; i++)
            {

                if (token.IsCancellationRequested)
                {
                    fs.Dispose();
                    Dispatcher.Invoke(() => File.WriteAllBytes(FilePath, bytes));
                    Dispatcher.Invoke(() => progressBar.Value = 0);
                    Dispatcher.Invoke(() => btnStart.IsEnabled = true);
                    return;
                }

                if (i != 0)
                    Dispatcher.Invoke(() => progressBar.Value = 100 * i / bytesToWrite.Length);

                fs.WriteByte(bytesToWrite[i]);
                Thread.Sleep(1);
            }

            fs.Seek(0, SeekOrigin.Begin);

            Dispatcher.Invoke(() => btnStart.IsEnabled = true);
            Dispatcher.Invoke(() => btnCancel.IsEnabled = false);
            Dispatcher.Invoke(() => progressBar.Value = 100);
        });
    }
    public byte[] Encryp(ref string ivAsBase64, ref string keyAsBase64, ref string encryptedTextAsBase64, string text, string password)
    {
        var aes = Aes.Create();

        aes.GenerateIV();
        byte[] iv = aes.IV;
        aes.KeySize = _keySize;
        ivAsBase64 = Convert.ToBase64String(iv);

        aes.GenerateKey();

        string key = password;

        byte[] keyBytes = Encoding.UTF8.GetBytes(key.Substring(0, aes.Key.Length));
        aes.Key = keyBytes;

        keyAsBase64 = Convert.ToBase64String(aes.Key);

        byte[] textBytes = Encoding.UTF8.GetBytes(text);
        var cryptor = aes.CreateEncryptor();
        byte[] encryptedBytes = cryptor.TransformFinalBlock(textBytes, 0, textBytes.Length);
        encryptedTextAsBase64 = Convert.ToBase64String(encryptedBytes);
        return encryptedBytes;

    }


    public byte[] Decryp(ref string ivAsBase64, ref string keyAsBase64, ref string encryptedTextAsBase64)
    {
        var aes = Aes.Create();
        aes.KeySize = _keySize;
        byte[] iv = Convert.FromBase64String(ivAsBase64);
        byte[] keyBytes = Convert.FromBase64String(keyAsBase64);
        byte[] fromBase64ToBytes = Convert.FromBase64String(encryptedTextAsBase64);

        var decryptor = aes.CreateDecryptor(keyBytes, iv);
        byte[] decryptedBytes = decryptor.TransformFinalBlock(fromBase64ToBytes, 0, fromBase64ToBytes.Length);
        return decryptedBytes;
    }



    private void btnCancel_Click(object sender, RoutedEventArgs e)
    {
        _cts?.Cancel();
        btnCancel.IsEnabled = false;

    }

}

