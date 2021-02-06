namespace Kerberos.Core

open DES.Utils
open Kerberos.Domain

module Tools =
    let private cryptAsResponseAttribute (attr: ASResponseAttribute) (key: string) (crypt): ASResponseAttribute =
        let tgsId = crypt attr.tgsId key
        let tgsSessionKey = crypt attr.tgsSessionKey key

        { attr with
              tgsId = tgsId
              tgsSessionKey = tgsSessionKey }

    let private cryptTgt (tgt: TicketGrantingTicket) (key: string) (crypt): TicketGrantingTicket =
        let tgsId = crypt tgt.tgsId key
        let userId = crypt tgt.userId key
        let tgsSessionKey = crypt tgt.tgsSessionKey key

        { tgt with
              tgsId = tgsId
              userId = userId
              tgsSessionKey = tgsSessionKey }

    let encryptTgt (tgt: TicketGrantingTicket) (key: string) = cryptTgt tgt key encrypt

    let decryptTgt (tgt: TicketGrantingTicket) (key: string) = cryptTgt tgt key decrypt

    let encryptAsResponseAttribute (attr: ASResponseAttribute) (key: string) =
        cryptAsResponseAttribute attr key encrypt

    let decryptAsResponseAttribute (attr: ASResponseAttribute) (key: string) =
        cryptAsResponseAttribute attr key decrypt