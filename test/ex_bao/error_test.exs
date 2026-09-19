defmodule ExBao.ErrorTest do
  use ExUnit.Case, async: true

  alias ExBao.Error

  describe "from_response/2" do
    test "a 403 is a permission problem whatever it says" do
      assert %Error{kind: :permission_denied, status: 403} =
               Error.from_response(403, %{"errors" => ["permission denied"]})
    end

    test "a 404 is not found" do
      assert %Error{kind: :not_found} = Error.from_response(404, %{"errors" => []})
    end

    # 503 is a sealed server, which is up and refusing on purpose. A caller
    # may want to wait it out, and it cannot if we call it a server error.
    test "a 503 is sealed, not a server error" do
      assert %Error{kind: :sealed} = Error.from_response(503, %{"errors" => ["Vault is sealed"]})
    end

    test "a 500 is a server error" do
      assert %Error{kind: :server_error} = Error.from_response(500, %{"errors" => ["boom"]})
    end

    test "a 429 is rate limiting" do
      assert %Error{kind: :rate_limited} = Error.from_response(429, %{"errors" => ["slow down"]})
    end

    # The one case where the prose decides, because the status cannot: a
    # corrupt row and a malformed request are both 400 and a caller handles
    # them differently.
    test "a 400 about ciphertext is told apart from a 400 about anything else" do
      assert %Error{kind: :invalid_ciphertext} =
               Error.from_response(400, %{"errors" => ["invalid ciphertext: bad format"]})

      assert %Error{kind: :invalid_request} =
               Error.from_response(400, %{"errors" => ["missing required field"]})
    end

    test "a 400 about credentials is told apart too" do
      assert %Error{kind: :invalid_credentials} =
               Error.from_response(400, %{"errors" => ["invalid role or secret ID"]})
    end

    test "an unknown status says so instead of guessing" do
      assert %Error{kind: :unknown} = Error.from_response(418, %{"errors" => ["teapot"]})
    end
  end

  describe "reading the body" do
    test "keeps the server's own words" do
      assert %Error{messages: ["one", "two"]} =
               Error.from_response(400, %{"errors" => ["one", "two"]})
    end

    # A proxy in front of the server answers HTML, and a plugin can answer a
    # bare string. Neither is the documented shape, and dropping them would
    # leave an error with nothing in it.
    test "survives a body that is not the documented shape" do
      assert %Error{messages: ["<html>502</html>"]} =
               Error.from_response(502, "<html>502</html>")

      assert %Error{messages: [_]} = Error.from_response(500, %{"weird" => true})
      assert %Error{messages: []} = Error.from_response(500, nil)
    end
  end

  describe "from_transport/1" do
    # Nothing answered, so there is no status. That distinction matters: a
    # transport error says nothing about whether the operation happened.
    test "has no status, because nothing replied" do
      assert %Error{kind: :transport, status: nil} =
               Error.from_transport(%Mint.TransportError{reason: :econnrefused})
    end
  end

  test "message/1 reads as one line" do
    error = Error.from_response(403, %{"errors" => ["permission denied"]})
    assert Exception.message(error) =~ "permission_denied"
    assert Exception.message(error) =~ "403"
    assert Exception.message(error) =~ "permission denied"
  end
end
