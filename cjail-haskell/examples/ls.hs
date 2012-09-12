module Main (main, ex) where

import Control.Monad
import CJail.System.Process
import System.IO
import qualified Data.ByteString.Lazy.Char8 as L8
import Data.List (intercalate)

main = do
  putStrLn "LS: "
  ls >>= putStrLn
  putStrLn "File echo: "
  ex >>= putStrLn

conf = CJailConf Nothing Nothing "/tmp/jail"

ls :: IO String
ls = do ph <- createProcess conf (shell "ls")
        hGetContents $ stdOut ph

sort :: [Int] -> IO [Int]
sort ls = do
  ph <- createProcess conf (proc "sort" ["-n"])
  let input = intercalate "\n" . map show $ ls
  hPutStrLn (stdIn ph) input
  hClose (stdIn ph)
  bs <- whileNotEOF (stdOut ph) []
  closeHandles ph
  return bs
    where whileNotEOF h acc = do
            eof <- hIsEOF  h
            if eof
              then return acc
              else do res <- read `liftM` hGetLine h
                      whileNotEOF h (res : acc)

ex :: IO String
ex =  do
  ph <- createProcess conf (shell "cat > /tmp/xxx ; cat /tmp/xxx")
  hPutStrLn (stdIn ph) "hello jail"
  hClose (stdIn ph)
  hGetContents $ stdOut ph
