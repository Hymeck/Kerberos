open System
open System.Net
open System.Text
open System.Threading.Tasks
open Kerberos.Client.KerberosClient
open Kerberos.Domain

let userId = "punk"
let serviceId = "punktionary"
let password = "punkPassword"
let userSecret = "[aObL_+p"

let ip = IPAddress.Parse("127.0.0.1")

let tgtLifetime = TimeSpan.FromSeconds(float 10)


[<EntryPoint>]
let main argv =
    Console.InputEncoding <- Encoding.UTF8
    Console.OutputEncoding <- Encoding.UTF8

    let userData =
        { userId = userId
          serviceId = serviceId
          ip = ip
          tgtLifetime = tgtLifetime }

    let asRequest = createASRequest userData

    Console.WriteLine(asRequest)
    let asResponse = sendASRequest asRequest

    match asResponse with
    | Some r -> Console.WriteLine(r)
    | None -> Console.WriteLine("User does not exist")

    let decodedAsResponse =
        decodeASResponse asResponse.Value userSecret

    Console.WriteLine()
    Console.WriteLine(decodedAsResponse)

    let tgsRequest =
        createTGSRequest asResponse.Value.tgt serviceId tgtLifetime userId decodedAsResponse.tgsSessionKey

    Console.WriteLine()
    Console.WriteLine(tgsRequest)

    let tgsResponse = sendTGSRequest tgsRequest
    Console.WriteLine()

    match tgsResponse with
    | Some r -> Console.WriteLine(r)
    | None -> Console.WriteLine("Something goes wrong with TGS")

    let decodedTgsResponse =
        decodeTGSResponse tgsResponse.Value decodedAsResponse.tgsSessionKey

    Console.WriteLine()
    Console.WriteLine(decodedTgsResponse)

    let serviceRequest =
        createServiceRequest tgsResponse.Value.serviceTicket userId decodedTgsResponse.serviceSessionKey
    
    Console.WriteLine()
    Console.WriteLine(serviceRequest)
    
    let serviceResponse = sendServiceRequest serviceRequest
    match serviceResponse with
    | Some r -> Console.WriteLine(r)
    | None -> Console.WriteLine("Something goes wrong with Service")
    
    Console.WriteLine()
    Console.WriteLine(serviceResponse)
    
    let decodedServiceResponse = decodeServiceResponse serviceResponse.Value decodedTgsResponse.serviceSessionKey
    Console.WriteLine()
    Console.WriteLine(decodedServiceResponse)
    0 // return an integer exit code