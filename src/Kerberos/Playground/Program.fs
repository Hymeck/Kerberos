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
    Console.WriteLine()
    Console.WriteLine(value)
    Console.WriteLine()

[<EntryPoint>]
let main argv =
    let userData =
        { userId = userId
          serviceId = serviceId
          ip = ip
          tgtLifetime = tgtLifetime }

    let asRequest = createASRequest userData

    printObject asRequest
    let asResponse = sendASRequest asRequest

    match asResponse with
    | Some r -> printObject r
    | None -> Console.WriteLine("User does not exist")

    let decodedAsResponse =
        decryptASResponse asResponse.Value (userSecret password)

    printObject decodedAsResponse

    let tgsRequest =
        createTGSRequest asResponse.Value.tgt serviceId tgtLifetime userId decodedAsResponse.tgsSessionKey

    printObject tgsRequest

    let tgsResponse = sendTGSRequest tgsRequest

    match tgsResponse with
    | Some r -> printObject r
    | None -> Console.WriteLine("Something goes wrong with TGS")

    let decodedTgsResponse =
        decryptTGSResponse tgsResponse.Value decodedAsResponse.tgsSessionKey

    printObject decodedTgsResponse

    let serviceRequest =
        createServiceRequest tgsResponse.Value.serviceTicket userId decodedTgsResponse.serviceSessionKey

    printObject serviceRequest

    let serviceResponse =
        sendServiceRequest serviceRequest serviceId

    match serviceResponse with
    | Some r -> printObject r
    | None -> Console.WriteLine("Something goes wrong with Service")

    printObject serviceResponse.Value

    let decodedServiceResponse =
        decryptServiceResponse serviceResponse.Value decodedTgsResponse.serviceSessionKey

    printObject decodedServiceResponse
    0
