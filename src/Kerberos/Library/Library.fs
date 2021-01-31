namespace Library

open System
open Library

module Kerberos =
    let rec normalizeLength (source: string): string =
        if ((source.Length * Constants.charSize) % Constants.blockSize) = 0
        then source
        else normalizeLength (source + string Constants.normalizeChar)

    let rec normalizeBinary (source: string): string =
        if source.Length = Constants.charSize
        then source
        else normalizeBinary (string Constants.zero + source)

    let toBinaryFormat (source: string): string =
        let binaryMapper (character: char) =
            normalizeBinary (Convert.ToString(int character, 2))

        String.collect binaryMapper source

    let toBlocks (normalizedSource: string): List<string> =
        let blockCount =
            normalizedSource.Length * Constants.charSize
            / Constants.blockSize

        let blockRange =
            seq { for i in 0 .. blockCount - 1 -> i }

        let chunkMapper chunkIndex =
            normalizedSource.Substring(chunkIndex * Constants.charPerBlock, Constants.charPerBlock)

        [ for block in (Seq.map chunkMapper blockRange) -> block |> toBinaryFormat ]