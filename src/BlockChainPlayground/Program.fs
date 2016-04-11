module Program

open BlockChainPlayground
open System

[<EntryPoint>]
let main (args : string []) = 

    let chapter = new BitcoinTransfer()
    chapter.BitcoinAddress()

    printf "Press any key to exit..."
    Console.ReadKey() |> ignore
    0
