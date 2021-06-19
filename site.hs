{-# LANGUAGE OverloadedStrings #-}

import Data.Char (isAscii, toLower)
import Data.Foldable (traverse_)
import Data.List (nub)
import Data.Maybe (mapMaybe)

import Crypto.Hash (Digest, SHA1, hash)
import Data.ByteArray (convert)
import qualified Data.ByteString.Base32.Z as Z
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Lazy.Char8 as L8
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Hakyll
import System.Process.Typed (proc, readProcess)

main :: IO ()
main = do
  keys <- words <$> getContents -- read stdin
  hakyll $ traverse_ wkdKey keys

type KeyId = String
type Uid = (String, String) -- ^ local-part, domain

wkdKey :: KeyId -> Rules ()
wkdKey keyId = do
  (status, out, err) <- preprocess . readProcess $
    proc "gpg2" ["--with-colons", "--list-keys", keyId]

  let
    uidLines = filter ("uid" `L8.isPrefixOf`) $ L8.lines out
    uidStrings = (!! 9) . L8.split ':' <$> uidLines
    uids = mapMaybe (parseMailbox . L8.unpack) uidStrings
    domains = nub (fmap snd uids)

  traverse_ wkdPolicy domains
  traverse_ (wkdUid keyId) uids

parseMailbox :: String -> Maybe Uid
parseMailbox s
  | length localPart > 0 && length domain > 0 = Just (localPart, domain)
  | otherwise = Nothing
  where
    (_, lt) = break (== '<') s
    (addr, _) = break (== '>') (drop 1 lt)
    (localPart, atDomain) = break (== '@') addr
    domain = drop 1 atDomain

wkdWellknown :: String {- ^ domain -} -> FilePath
wkdWellknown domain = ".well-known/openpgpkey/" <> domain <> "/"

wkdPolicy :: String {- ^ domain -} -> Rules ()
wkdPolicy domain =
  create [fromFilePath $ wkdWellknown domain <> "policy"] $ do
    route idRoute
    compile $ makeItem ("" :: String)

wkdUid :: KeyId -> Uid -> Rules ()
wkdUid keyId uid@(localPart, domain) = do
  let path = wkdWellknown domain <> "hu/" <> hashLocalPart localPart
  create [fromFilePath path] $ do
    route $ idRoute
    compile $ exportKey keyId uid

hashLocalPart :: String -> String
hashLocalPart localPart =
  let
    digest :: Digest SHA1
    digest = hash . T.encodeUtf8 . T.pack . toLowerAscii $ localPart
  in
    B8.unpack . Z.encode . convert $ digest

exportKey :: KeyId -> Uid -> Compiler (Item L8.ByteString)
exportKey keyId (localPart, domain) = do
  (status, out, err) <- unsafeCompiler . readProcess $
    proc "gpg2"
      [ "--export-filter", "keep-uid=mbox=" <> localPart <> "@" <> domain
      , "--export", keyId
      ]
  makeItem out

-- | ASCII chars to lower case, other chars unchanged
toLowerAscii :: String -> String
toLowerAscii = fmap (\c -> if isAscii c then toLower c else c)
