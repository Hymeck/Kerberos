namespace DES

module Constants =
    let charSize = 16
    let blockSize = 128
    let charPerBlock = blockSize / charSize
    let keyShift = 2
    let roundCount = 16
    let normalizeChar = '#'
    let zero = '0'
