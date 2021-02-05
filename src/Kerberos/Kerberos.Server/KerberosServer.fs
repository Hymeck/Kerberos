namespace Kerberos.Server

open System
open System.Collections.Generic
open System.Collections.Immutable
open Kerberos.Domain
open Kerberos.Core.Core

module KerberosServer =
    let tgsId = "aPxlOvrnj10-"
    let tgsSecretKey = "zi#gml+ltM"
    let generateTgsSessionKey = Guid.NewGuid().ToString()
    let userDictionary =
        let userDictionary = Dictionary<string, string>()
        userDictionary.Add("metalist", "metalistSecretKey")
        userDictionary.Add("punk","punkSecretKey")
        userDictionary.Add("drocher","drocherSecretKey")
        userDictionary
        
    let sendASResponse (request: ASRequest): Option<ASResponse> =
        let users = userDictionary
        if not (users.ContainsKey request.userId) then None
        else
            let tgsId = tgsId
            let timestamp = DateTime.Now.Ticks.ToString()
            let lifetime = (TimeSpan.FromSeconds (float 30)).Ticks.ToString()
            let tgsSessionKey = generateTgsSessionKey
            let tgt = {userId = request.userId; tgsId = tgsId; timestamp = timestamp; userIpAddress = ImmutableList.Create(request.ipAddress); lifetime = lifetime; tgsSessionKey = tgsSessionKey}
            let attribute = {tgsId = tgsId; timestamp = timestamp; lifetime = lifetime; tgsSessionKey = tgsSessionKey}
            let response = {attribute = attribute; tgt = tgt}
            Some(encryptASResponse response (users.[request.userId]) (tgsSecretKey))
            
            