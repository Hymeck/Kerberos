namespace Kerberos

open System

module Core =
    type UserIdentifier = { login: string; password: string }

    type TGSIdentifier = { identifier: string }

    // todo: keys for TGT?
    type TGT =
        { userIdentifier: UserIdentifier
          tgsIdentifier: TGSIdentifier
          at: DateTime
          duration: TimeSpan }

    // todo: keys for AR response?
    type ASResponse = {tgt: TGT; }
    
    type Aut = {userIdentifier: UserIdentifier; at: DateTime}