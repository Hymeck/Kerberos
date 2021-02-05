open System
open System.Net
open System.Text
open System.Threading.Tasks
open Kerberos.Client.KerberosClient

let userId = "punk"
let serviceId = "punktionary.com"
let password = "punkPassword"
let userSecret = "punkSecretKey"

let ip = IPAddress.Parse("127.0.0.1")

let tgtLifetime = TimeSpan.FromSeconds (float 10)


[<EntryPoint>]
let main argv =
    Console.InputEncoding <- Encoding.UTF8
    Console.OutputEncoding <- Encoding.UTF8
    let userData = {userId = userId; serviceId = serviceId; ip = ip; tgtLifetime = tgtLifetime}
    
    let asRequest = createASRequest userData
    
    Console.WriteLine(asRequest)
    Task.Delay(1000) |> ignore
    let response = sendASRequest asRequest
    match response with
    | Some r ->
        Console.WriteLine(r)
    | None -> Console.WriteLine("User does not exist")
    
    let d = decodeASResponseAttribute response.Value userSecret
    Console.WriteLine(d)
    0 // return an integer exit code