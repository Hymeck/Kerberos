namespace DES

open System
open System.Collections.Immutable
open System.Linq

module Kerberos =
    let private isCorrectSize (source: string): bool =
        (source.Length * Constants.charSize) % Constants.blockSize = 0

    let rec normalizeLength (source: string): string =
        if isCorrectSize source
        then source
        else normalizeLength (source + string Constants.normalizeChar)

    let rec private normalizeBinary (binarySource: string): string =
        if binarySource.Length = Constants.charSize
        then binarySource
        else normalizeBinary (string Constants.zero + binarySource)

    let toBinaryFormat (source: string): string =
        let binaryMapper (character: char) =
            normalizeBinary (Convert.ToString(int character, 2))

        String.collect binaryMapper source

    let toBinaryBlocks (normalizedSource: string): ImmutableList<string> =
        let blockCount =
            normalizedSource.Length * Constants.charSize
            / Constants.blockSize

        let blockRange =
            seq { for i in 0 .. blockCount - 1 -> i }

        let chunkMapper chunkIndex =
            normalizedSource.Substring(chunkIndex * Constants.charPerBlock, Constants.charPerBlock)
            |> toBinaryFormat

        ImmutableList.ToImmutableList(Seq.map chunkMapper blockRange)

    let normalizeKey (key: string) (keyLength: int): string =
        if key.Length > keyLength then
            key.Substring(0, keyLength)
        else
            let zeroLength = keyLength - key.Length

            (String.replicate zeroLength (string Constants.zero))
            + key

    let private charXor (pair: char * char): char =
        let left, right = pair

        let l =
            Convert.ToBoolean(Convert.ToInt32(string left))

        let r =
            Convert.ToBoolean(Convert.ToInt32(string right))

        if (l <> r) then '1' else '0'

    let private xor (left: string) (right: string) =
        Seq.zip left right
        |> Seq.map charXor
        |> Seq.toArray
        |> fun cs -> new string(cs)

    let private encryptionFunction (left: string) (right: string): string = xor left right

    let private desEncode (input: string) (key: string): string =
        let middle = input.Length / 2
        let left = input.Substring(0, middle)
        let right = input.Substring(middle)
        // right + xor ( left, encryptionFunction ( right, key ) )
        right
        + (key |> encryptionFunction right |> xor left)

    let private desDecode (input: string) (key: string): string =
        let middle = input.Length / 2
        let left = input.Substring(0, middle)
        let right = input.Substring(middle)
        // xor ( encryptionFunction ( left, key ),  right)  + left
        (right |> xor (key |> encryptionFunction left))
        + left

    let private shiftRight (key: string): string =
        let addToStart (str: string) = string (str.Chars(str.Length - 1)) + str
        let removeLast (str: string) = str.Remove(str.Length - 1, 1)

        let mutable shiftedKey = key

        for i in 1 .. Constants.keyShift do
            shiftedKey <- shiftedKey |> addToStart |> removeLast

        shiftedKey

    let private shiftLeft (key: string): string =
        let addToEnd (str: string) = str + string (str.Chars(0))
        let removeFirst (str: string) = str.Remove(0, 1)

        let mutable shiftedKey = key

        for i in 1 .. Constants.keyShift do
            shiftedKey <- shiftedKey |> addToEnd |> removeFirst

        shiftedKey

    let private parseChunk (binaryChunk: string): char =
        let mutable degree = binaryChunk.Length - 1
        let mutable result = 0

        for digit in binaryChunk do
            let parsedDigit =
                Convert.ToInt32(string digit)
                * int (Math.Pow(float 2, float degree))

            result <- result + parsedDigit
            degree <- degree - 1

        char result

    let fromBinaryFormat (binarySource: string) =
        let chunk (chunkIndex: int) =
            binarySource.Substring(chunkIndex * Constants.charSize, Constants.charSize)

        let range =
            seq { for i in 1 .. binarySource.Length / Constants.charSize -> i - 1 }

        let chunks = Seq.map chunk range

        Seq.map parseChunk chunks
        |> Seq.toArray
        |> fun cs -> new string(cs)

    let private crypt (binaryBlocks: ImmutableList<string>) (binaryNormalizedKey: string) desCode shift finalShift =
        let mutable blocks = binaryBlocks.ToArray()
        let mutable key = binaryNormalizedKey

        for i in 1 .. Constants.roundCount do
            for block in 0 .. binaryBlocks.Count - 1 do
                blocks.[block] <- (desCode blocks.[block] key)

            key <- shift key

        key <- finalShift key
        (binaryBlocks, key)

    let encrypt (binaryBlocks: ImmutableList<string>) (binaryNormalizedKey: string) =
        crypt binaryBlocks binaryNormalizedKey desEncode shiftRight shiftLeft

    let decrypt (binaryBlocks: ImmutableList<string>) (binaryNormalizedKey: string) =
        crypt binaryBlocks binaryNormalizedKey desDecode shiftLeft shiftRight