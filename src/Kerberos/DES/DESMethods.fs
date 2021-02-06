namespace DES

open System
open System.IO
open System.Text
open System.Security.Cryptography

module DESMethods =

    let crypt (source: string) (key: string) (cryptTransform) (bytesFromStr) =
        let sourceBytes = bytesFromStr source
        let keyBytes = Encoding.UTF8.GetBytes(key)

        let transform = cryptTransform (keyBytes, keyBytes)

        let memory = new MemoryStream()

        let crypt =
            new CryptoStream(memory, transform, CryptoStreamMode.Write)

        crypt.Write(sourceBytes, 0, sourceBytes.Length)
        crypt.FlushFinalBlock()

        let result = Array.zeroCreate (int memory.Length)
        memory.Position <- int64 0

        memory.Read(result, 0, result.Length) |> ignore

        memory.Close()
        crypt.Close()

        result

    let encrypt (source: string) (key: string): string =
        let desProvider = new DESCryptoServiceProvider()

        (crypt source key desProvider.CreateEncryptor Encoding.UTF8.GetBytes)
        |> Convert.ToBase64String

    let decrypt (source: string) (key: string): string =
        let desProvider = new DESCryptoServiceProvider()

        (crypt source key desProvider.CreateDecryptor Convert.FromBase64String)
        |> Encoding.UTF8.GetString