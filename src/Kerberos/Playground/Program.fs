open System
open System.Net
open Kerberos.Client.KerberosClient
open Kerberos.Domain

let userId = "punk"
let serviceId = "punktionary"
let password = "punkPassword"
let userSecret (password: string) = "[aObL_+p"

let ip = IPAddress.Parse("127.0.0.1")

let tgtLifetime = TimeSpan.FromSeconds(float 10)

let printObject (value: obj) =
    Console.WriteLine(value)

let printInfo (info: string) =
    Console.WriteLine(info)

let printInfoWithObject (info: string) (value: obj) =
    Console.WriteLine("---")
    printInfo info
    printObject value
    Console.WriteLine("---")
    Console.WriteLine()

[<EntryPoint>]
let main argv =
    let userData =
        { userId = userId
          serviceId = serviceId
          ip = ip
          tgtLifetime = tgtLifetime }

    let asRequest = createASRequest userData

    printInfoWithObject "1. Request to AS:" asRequest
    let asResponse = sendASRequest asRequest

    match asResponse with
    | Some r -> printInfoWithObject "2. AS response:" r
    | None -> Console.WriteLine("User does not exist.")

    let decodedAsResponse =
        decryptASResponse asResponse.Value (userSecret password)

    printInfoWithObject "Decrypted AS value using user secret key: " decodedAsResponse

    let tgsRequest =
        createTGSRequest asResponse.Value.tgt serviceId tgtLifetime userId decodedAsResponse.tgsSessionKey

    printInfoWithObject "3. Request to TGS:" tgsRequest

    let tgsResponse = sendTGSRequest tgsRequest

    match tgsResponse with
    | Some r -> printInfoWithObject "4. TGS response:" r
    | None -> Console.WriteLine("Something goes wrong with TGS.")

    let decodedTgsResponse =
        decryptTGSResponse tgsResponse.Value decodedAsResponse.tgsSessionKey

    printInfoWithObject "Decrypted TGS value using TGS session key:" decodedTgsResponse

    let serviceRequest =
        createServiceRequest tgsResponse.Value.serviceTicket userId decodedTgsResponse.serviceSessionKey

    printInfoWithObject "5. Service request:" serviceRequest

    let serviceResponse =
        sendServiceRequest serviceRequest serviceId

    match serviceResponse with
    | Some r -> printInfoWithObject "6. Service response:" r
    | None -> Console.WriteLine("Something goes wrong with Service.")

    let decodedServiceResponse =
        decryptServiceResponse serviceResponse.Value decodedTgsResponse.serviceSessionKey

    printInfoWithObject "Decrypted Service value using service session key:" decodedServiceResponse
    0
