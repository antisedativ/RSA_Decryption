defmodule RSA do
  defmodule Key do
    defstruct [:public_key, :private_key]

    def generate_keys(n, q) do
      p = generate_prime(n)
      phi = (p - 1) * (q - 1)
      e = generate_public_key(phi)
      d = generate_private_key(e, phi)
      %Key{public_key: {e, n}, private_key: {d, n}}
    end

    defp generate_prime(n) do
      case is_prime(n) do
        true -> n
        false -> generate_prime(n + 1)
      end
    end

    defp is_prime(n) when n <= 1, do: false
    defp is_prime(2), do: true
    defp is_prime(n) do
      not Enum.any?(2..round(:math.sqrt(n)), &rem(n, &1) == 0)
    end

    defp generate_public_key(phi) do
      e = 65537
      generate_valid_e(e, phi)
    end

    defp generate_valid_e(e, phi) do
      if is_coprime(e, phi) do
        e
      else
        raise "Failed to generate valid public key"
      end
    end

    defp is_coprime(_a, b) when b <= 0, do: false
    defp is_coprime(a, b) when rem(b, a) == 0, do: false
    defp is_coprime(_, _), do: true

    defp generate_private_key(e, phi) do
      {d, _, _} = ext_euclidean_algorithm(e, phi)
      d = if d < 0, do: phi + d, else: d
      d
    end

    defp ext_euclidean_algorithm(a, b) when b == 0, do: {1, 0, a}
    defp ext_euclidean_algorithm(a, b) do
      {x, y, d} = ext_euclidean_algorithm(b, rem(a, b))
      {y, x - div(a, b) * y, d}
    end
  end

  def encrypt(message, {e, n}) do
    :crypto.mod_pow(message, e, n)
  end

  def decrypt(ciphertext, {d, n}) do
    decrypted_hex = :crypto.mod_pow(ciphertext, d, n)
    String.to_integer(Base.encode16(decrypted_hex))
  end

  def to_hex(binary_data) do
    binary_data
    |> Base.encode16()
    |> String.upcase()
  end
end

# Пример использования
key_pair = RSA.Key.generate_keys(61, 53)
IO.inspect key_pair

original_message = 37
IO.puts "Original message: #{original_message}"

encrypted_message = RSA.encrypt(original_message, key_pair.public_key)
IO.puts "Encrypted message (hex): #{RSA.to_hex(encrypted_message)}"

decrypted_message = RSA.decrypt(encrypted_message, key_pair.private_key)
IO.puts "Decrypted message: #{decrypted_message}"
