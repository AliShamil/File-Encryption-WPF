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
    private CancellationTokenSource _cts;

    public MainWindow()
    {
        InitializeComponent();
    }

    private void BrowseButton_Click(object sender, RoutedEventArgs e)
    {
        var openFileDialog = new OpenFileDialog();
        if (openFileDialog.ShowDialog() == true)
        {
            txtPath.Text = openFileDialog.FileName;
        }
    }

    private void StartButton_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(txtPath.Text))
        {
            MessageBox.Show("Please choose a file.");
            return;
        }

        if (string.IsNullOrEmpty(txtPassword.Password))
        {
            MessageBox.Show("Please enter a password.");
            return;
        }

        if (!File.Exists(txtPath.Text))
        {
            MessageBox.Show("The selected file does not exist.");
            return;
        }

        bool isEncryptMode = rbtnEncrypt.IsChecked == true;
        if (isEncryptMode && File.Exists(txtPath.Text + ".encrypted"))
        {
            MessageBox.Show("The file has already been encrypted.");
            return;
        }

        if (!isEncryptMode && !File.Exists(txtPath.Text + ".encrypted"))
        {
            MessageBox.Show("The file has not been encrypted.");
            return;
        }

        btnStart.IsEnabled = false;
        btnSelectPath.IsEnabled = false;
        btnCancel.IsEnabled = true;

        _cts = new CancellationTokenSource();
        var cancellationToken = _cts.Token;

        ThreadPool.QueueUserWorkItem(state =>
        {
            try
            {

                if (isEncryptMode)
                {

                    this.Dispatcher.Invoke(() =>
                    {
                    EncryptFile(txtPath.Text, txtPath.Text + ".encrypted", txtPassword.Password, cancellationToken);
                        
                    });
                }
                else
                {

                    this.Dispatcher.Invoke(() =>
                    {
                    DecryptFile(txtPath.Text + ".encrypted", txtPath.Text, txtPassword.Password, cancellationToken);
                        
                    });
                }

                this.Dispatcher.Invoke(() =>
                {
                    MessageBox.Show("Done!");
                });
            }
            catch (OperationCanceledException)
            {
                this.Dispatcher.Invoke(() =>
                {
                    MessageBox.Show("Canceled.");
                });
            }
            catch (Exception ex)
            {
                this.Dispatcher.Invoke(() =>
                {
                    MessageBox.Show("Error: " + ex.Message);
                });
            }
            finally
            {
                this.Dispatcher.Invoke(() =>
                {
                    btnStart.IsEnabled = true;
                    btnSelectPath.IsEnabled = true;
                    btnCancel.IsEnabled = false;
                    progressBar.Value = 0;
                });
            }
        });
    }

    private void EncryptFile(string inputFilePath, string outputFilePath, string password, CancellationToken cancellationToken)
    {
        using var inputStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read);
        using var outputStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write);

        var aes = Aes.Create();
        aes.Key = GetKey(password, aes);
        aes.IV = GetRandomBytes(16);

        var encryptor = aes.CreateEncryptor();

        using var cryptoStream = new CryptoStream(outputStream, encryptor, CryptoStreamMode.Write);

        var buffer = new byte[4096];
        long totalBytes = inputStream.Length;
        long processedBytes = 0;

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            int bytesRead = inputStream.Read(buffer, 0, buffer.Length);
            Thread.Sleep(1500);
            if (bytesRead == 0) break;

            cryptoStream.Write(buffer, 0, bytesRead);
            processedBytes += bytesRead;
            int progress = (int)Math.Round(processedBytes * 100.0 / totalBytes);
            progressBar.Value = progress;
        }
        inputStream.Seek(0, SeekOrigin.Begin);
        outputStream.Seek(0, SeekOrigin.Begin);
        outputStream.Flush();
    }

    private void DecryptFile(string inputFilePath, string outputFilePath, string password, CancellationToken cancellationToken)
    {
        using var inputStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read);
        using var outputStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write);

        var aes = Aes.Create();
        aes.Key = GetKey(password, aes);
        aes.IV = GetRandomBytes(16);

        var decryptor = aes.CreateDecryptor();

        using var cryptoStream = new CryptoStream(inputStream, decryptor, CryptoStreamMode.Read);

        var buffer = new byte[4096];
        long totalBytes = inputStream.Length;
        long processedBytes = 0;

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            int bytesRead = cryptoStream.Read(buffer, 0, buffer.Length);
            Thread.Sleep(1500);
            if (bytesRead == 0) break;

            outputStream.Write(buffer, 0, bytesRead);

            processedBytes += bytesRead;
            int progress = (int)Math.Round(processedBytes * 100.0 / totalBytes);
            progressBar.Value = progress;
        }
        inputStream.Seek(0, SeekOrigin.Begin);
        outputStream.Seek(0, SeekOrigin.Begin);
        outputStream.Flush();
    }

    private void CancelButton_Click(object sender, RoutedEventArgs e)
    {
        _cts?.Cancel();
    }



    private byte[] GetKey(string password, SymmetricAlgorithm algorithm)
    {
        var salt = new byte[8];
        using var rng = new RNGCryptoServiceProvider();
        rng.GetBytes(salt);

        var deriveBytes = new Rfc2898DeriveBytes(password, salt, 10000);
        return deriveBytes.GetBytes(algorithm.KeySize / 8);
    }

    private byte[] GetRandomBytes(int size)
    {
        var bytes = new byte[size];
        using var rng = new RNGCryptoServiceProvider();
        rng.GetBytes(bytes);
        return bytes;
    }

}

