{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE PolyKinds                  #-}
{-# LANGUAGE TupleSections              #-}
{-# LANGUAGE UndecidableInstances       #-}

module Servant.Auth.Server.Internal.AddSetCookie where


import           Blaze.ByteString.Builder (toByteString)
import           Network.Wai              (mapResponseHeaders)
import qualified Data.ByteString          as BS
import qualified Data.ByteString.Base64   as BS64
import qualified Network.HTTP.Types       as HTTP
import           Servant
import           System.Entropy (getEntropy)
import           Web.Cookie

-- What are we doing here? Well, the idea is to add headers to the response,
-- but the headers come from the authentication check. In order to do that, we
-- tweak a little the general theme of recursing down the API tree; this time,
-- we recurse down a variation of it that adds headers to all the endpoints.
-- This involves the usual type-level checks.
--
-- TODO: If the endpoints already have headers, this will not work as is.

data Nat = Z | S Nat

type family AddSetCookiesApi (n :: Nat) a where
  AddSetCookiesApi ('S 'Z) a = AddSetCookieApi a
  AddSetCookiesApi ('S n) a = AddSetCookiesApi n (AddSetCookieApi a)

type family AddSetCookieApi a where
  AddSetCookieApi (a :> b) = a :> AddSetCookieApi b
  AddSetCookieApi (a :<|> b) = AddSetCookieApi a :<|> AddSetCookieApi b
  AddSetCookieApi (Verb method stat ctyps (Headers ls a))
     = Verb method stat ctyps (Headers ((Header "Set-Cookie" SetCookie) ': ls) a)
  AddSetCookieApi (Verb method stat ctyps a)
     = Verb method stat ctyps (Headers '[Header "Set-Cookie" SetCookie] a)
  AddSetCookieApi Raw = Raw

data SetCookieList (n :: Nat) :: * where
  SetCookieNil :: SetCookieList 'Z
  SetCookieCons :: Maybe SetCookie -> SetCookieList n -> SetCookieList ('S n)

class AddSetCookies (n :: Nat) orig new where
  addSetCookies :: SetCookieList n -> orig -> new

instance {-# OVERLAPS #-} AddSetCookies ('S n) oldb newb
  => AddSetCookies ('S n) (a -> oldb) (a -> newb) where
  addSetCookies cookies oldfn = \val -> addSetCookies cookies $ oldfn val

instance AddSetCookies 'Z orig orig where
  addSetCookies _ = id

instance {-# OVERLAPPABLE #-}
  ( Functor m
  , AddSetCookies n (m old) (m cookied)
  , AddHeader "Set-Cookie" SetCookie cookied new
  ) => AddSetCookies ('S n) (m old) (m new)  where
  addSetCookies (mCookie `SetCookieCons` rest) oldVal =
    case mCookie of
      Nothing -> noHeader <$> addSetCookies rest oldVal
      Just cookie -> addHeader cookie <$> addSetCookies rest oldVal

instance {-# OVERLAPS #-}
  (AddSetCookies ('S n) a a', AddSetCookies ('S n) b b')
  => AddSetCookies ('S n) (a :<|> b) (a' :<|> b') where
  addSetCookies cookies (a :<|> b) = addSetCookies cookies a :<|> addSetCookies cookies b

instance
  AddSetCookies ('S n) Application Application where
  addSetCookies cookies r request respond
    = r request (\response -> respond
               $ mapResponseHeaders (++ mkHeaders cookies) response)

mkHeaders :: SetCookieList x -> [HTTP.Header]
mkHeaders x = ("Set-Cookie",) <$> mkCookies x
  where
   mkCookies :: forall y. SetCookieList y -> [BS.ByteString]
   mkCookies SetCookieNil = []
   mkCookies (SetCookieCons Nothing rest) = mkCookies rest
   mkCookies (SetCookieCons (Just y) rest)
     = toByteString (renderSetCookie y) : mkCookies rest

csrfCookie :: IO BS.ByteString
csrfCookie = BS64.encode <$> getEntropy 32
