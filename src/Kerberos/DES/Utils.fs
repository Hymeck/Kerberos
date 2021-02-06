namespace DES

open System
open System.IO
open System.Text
open System.Security.Cryptography
open System.Collections.Immutable
open System.Linq
open Constants

module Utils =
    //    let private isCorrectSize (source: string): bool =
//        (source.Length * charSize) % blockSize = 0
//
//    let rec private normalizeLength (source: string): string =
//        if isCorrectSize source
//        then source
//        else normalizeLength (source + string normalizeChar)
//
//    let rec private normalizeBinary (binarySource: string): string =
//        if binarySource.Length = charSize
//        then binarySource
//        else normalizeBinary (string zero + binarySource)
//
//    let private toBinaryFormat (source: string): string =
//        let binaryMapper (ch: char) =
//            normalizeBinary (Convert.ToString(int ch, 2))
//
//        String.collect binaryMapper source
//
//    let private toBinaryBlocks (normalizedSource: string): ImmutableList<string> =
//        let blockCount =
//            (normalizedSource.Length * charSize) / blockSize
//
//        let blockRange =
//            seq { for i in 0 .. blockCount - 1 -> i }
//
//        let blockLength = normalizedSource.Length / blockCount
//
//        let chunkMapper chunkIndex =
//            normalizedSource.Substring(chunkIndex * blockLength, blockLength)
//            |> toBinaryFormat
//
//        ImmutableList.ToImmutableList(Seq.map chunkMapper blockRange)
//
//    let private normalizeKey (key: string) (keyLength: int): string =
//        if key.Length > keyLength then
//            key.Substring(0, keyLength)
//        else
//            let zeroLength = keyLength - key.Length
//
//            (String.replicate zeroLength (string zero)) + key
//
//    let private toBool (ch: char) =
//        Convert.ToBoolean(Convert.ToInt32(string ch))
//
//    let private charXor (pair: char * char): char =
//        let left, right = pair
//        let l = toBool left
//        let r = toBool right
//
//        if (l <> r) then '1' else '0'
//
//    let private xor (left: string) (right: string): string =
//        Seq.zip left right
//        |> Seq.map charXor
//        |> Seq.toArray
//        |> fun cs -> new string(cs)
//
//    let private encryptionFunction (left: string) (right: string): string = xor left right
//
//    let private pair (input: string): string * string =
//        let middle = input.Length / 2
//        let left = input.Substring(0, middle)
//        let right = input.Substring(middle)
//        (left, right)
//
//    let private desEncode (input: string) (key: string): string =
//        let (left, right) = pair input
//        right + (xor left (encryptionFunction right key))
//
//    let private desDecode (input: string) (key: string): string =
//        let (left, right) = pair input
//        (xor (encryptionFunction left key) right) + left
//
//    let private shift (key: string) (add) (remove): string =
//        let mutable shiftedKey = key
//
//        for i in 1 .. keyShift do
//            shiftedKey <- shiftedKey |> add |> remove
//
//        shiftedKey
//
//    let private shiftRight (key: string): string =
//        let addToStart (str: string) = string (str.Chars(str.Length - 1)) + str
//        let removeLast (str: string) = str.Remove(str.Length - 1, 1)
//        shift key addToStart removeLast
//
//    let private shiftLeft (key: string): string =
//        let addToEnd (str: string) = str + string (str.Chars(0))
//        let removeFirst (str: string) = str.Remove(0, 1)
//        shift key addToEnd removeFirst
//
//    let private parseChunk (binaryChunk: string): char =
//        let mutable degree = binaryChunk.Length - 1
//        let mutable result = 0
//
//        for digit in binaryChunk do
//            let parsedDigit =
//                Convert.ToInt32(string digit)
//                * int (Math.Pow(float 2, float degree))
//
//            result <- result + parsedDigit
//            degree <- degree - 1
//
//        char result
//
//    let private fromBinaryFormat (binarySource: string): string =
//        let chunk (chunkIndex: int) =
//            binarySource.Substring(chunkIndex * charSize, charSize)
//
//        let range =
//            seq { for i in 1 .. binarySource.Length / charSize -> i - 1 }
//
//        let chunks = Seq.map chunk range
//
//        Seq.map parseChunk chunks
//        |> Seq.toArray
//        |> fun cs -> new string(cs)
//
//    let private crypt (binaryBlocks: ImmutableList<string>) (binaryNormalizedKey: string) des shift finalShift =
//        let mutable blocks = binaryBlocks.ToArray()
//        let mutable key = binaryNormalizedKey
//
//        for i in 1 .. roundCount do
//            for block in 0 .. binaryBlocks.Count - 1 do
//                blocks.[block] <- (des blocks.[block] key)
//
//            key <- shift key
//
//        key <- finalShift key
//        (ImmutableList.ToImmutableList blocks, key)
//
//    let private toNormalFormat (binaryBlocks: ImmutableList<string>): string =
//        (String.Empty, binaryBlocks)
//        |> String.Join
//        |> fromBinaryFormat
//
//    let private cipher (binaryBlocks: ImmutableList<string>) (binaryNormalizedKey: string) =
//        crypt binaryBlocks binaryNormalizedKey desEncode shiftRight shiftLeft
//
//    let private decipher (binaryBlocks: ImmutableList<string>) (binaryNormalizedKey: string) =
//        crypt binaryBlocks binaryNormalizedKey desDecode shiftLeft shiftRight
//
//    let private fullCrypt (source: string) (key: string) (cryptFunction): string =
//        let normalizedInput = normalizeLength source
//
//        let binaryBlocks = normalizedInput |> toBinaryBlocks
//
//        let binaryKey =
//            normalizeKey key (normalizedInput.Length / (2 * binaryBlocks.Count))
//            |> toBinaryFormat
//
//        let (blocks, _) = cryptFunction binaryBlocks binaryKey
//
//        (toNormalFormat blocks)
//            .Substring(0, source.Length)
//
//    let encrypt (source: string) (key: string) = fullCrypt source key cipher
//
////    let decrypt (source: string) (key: string) = fullCrypt source key decipher
//    let decrypt (source: string) (key: string) =
//        let normalizedInput = normalizeLength source
//
//        let binaryBlocks = normalizedInput |> toBinaryBlocks
//
//        let binaryKey =
//            normalizeKey key (normalizedInput.Length / (2 * binaryBlocks.Count))
//            |> toBinaryFormat
//
//        let (blocks, _) = decipher binaryBlocks binaryKey
//
//        (toNormalFormat blocks)
//            .Substring(0, source.Length)
//
//    let coolEncrypt (data: string) (key: byte[]) (iv: byte[]) =
//        let mStream = new MemoryStream()
//        let des = DES.Create()
//        let cStream = new CryptoStream(mStream, des.CreateEncryptor(key, iv), CryptoStreamMode.Write)
//        let toEncrypt = Encoding.UTF8.GetBytes(data);
//        cStream.Write(toEncrypt, 0, toEncrypt.Length);
//        cStream.FlushFinalBlock()
//        let result = mStream.ToArray();
//        cStream.Close();
//        mStream.Close()
//        Encoding.ASCII.GetString result
//
//    let coolDecrypt (data: string) (key: byte[]) (iv: byte[]) =
//        let data = Encoding.ASCII.GetBytes data
//        let msDecrypt = new MemoryStream(data)
//        let des = DES.Create()
//        let csDecrypt = new CryptoStream(msDecrypt, des.CreateDecryptor(key, iv), CryptoStreamMode.Read)
//        let fromEncrypt = Array.zeroCreate data.Length
//        csDecrypt.Read(fromEncrypt, 0, fromEncrypt.Length) |> ignore
//        msDecrypt.Close()
//        csDecrypt.Close()
//        ASCIIEncoding().GetString(fromEncrypt);
    let encrypt (input: string) (key: string): string =
        let messageBytes = Encoding.UTF8.GetBytes(input)
        let keywordBytes = Encoding.UTF8.GetBytes(key)

        let provider = new DESCryptoServiceProvider()

        let transform =
            provider.CreateEncryptor(keywordBytes, keywordBytes)

        let mode = CryptoStreamMode.Write

        let memStream = new MemoryStream()

        let cryptoStream =
            new CryptoStream(memStream, transform, mode)

        cryptoStream.Write(messageBytes, 0, messageBytes.Length)
        cryptoStream.FlushFinalBlock()

        let encryptedMessageBytes = Array.zeroCreate (int memStream.Length)
        memStream.Position <- int64 0

        memStream.Read(encryptedMessageBytes, 0, encryptedMessageBytes.Length)
        |> ignore

        memStream.Close()
        cryptoStream.Close()

        Convert.ToBase64String(encryptedMessageBytes)

    let decrypt (input: string) (key: string): string =
        let encryptedMessageBytes = Convert.FromBase64String(input)
        let passwordBytes = Encoding.UTF8.GetBytes(key)

        let provider = new DESCryptoServiceProvider()

        let transform =
            provider.CreateDecryptor(passwordBytes, passwordBytes)

        let mode = CryptoStreamMode.Write

        let memStream = new MemoryStream()

        let cryptoStream =
            new CryptoStream(memStream, transform, mode)

        cryptoStream.Write(encryptedMessageBytes, 0, encryptedMessageBytes.Length)
        cryptoStream.FlushFinalBlock()

        let decryptedMessageBytes = Array.zeroCreate (int memStream.Length)
        memStream.Position <- int64 0

        memStream.Read(decryptedMessageBytes, 0, decryptedMessageBytes.Length)
        |> ignore

        memStream.Close()
        cryptoStream.Close()

        Encoding.UTF8.GetString(decryptedMessageBytes)