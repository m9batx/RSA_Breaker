# RSA analyzer based on Fermat's Factorization Method

This project demonstrates a simple mathematical attack against RSA by finding the two factors of the RSA modulus `N`, namely `p` and `q`.

The factorization functions are implemented separately in the `Nfactores` files and then integrated into `RSA.c`.

## Fermat's Factorization Method

The RSA attack in this project is based on **Fermat's factorization method**, which can be used to factor the modulus `N` into its prime factors `p` and `q`.

Fermat's method is based on the difference of squares:

```text
N = a² - b²
  = (a + b)(a - b)
```

Therefore:

```text
p = a + b
q = a - b
```

## Implementation Steps

1. Find the smallest integer `a` such that:

```text
a² > N
```

2. Calculate:

```text
b² = a² - N
```

3. Check whether `b²` is a perfect square.

* If it is not a perfect square, increase `a` and calculate `b²` again.
* If it is a perfect square, calculate `b = √b²`.

4. After obtaining `a` and `b`, calculate the factors:

```text
p = a + b
q = a - b
```

5. Check whether:

```text
q × p = N
```

If the result is correct, `N` has been successfully factored.

6. Finally, calculate the RSA private key `d` as the modular inverse of `e` modulo `φ(N)`:

```text
φ(N) = (p - 1)(q - 1)

d = e⁻¹ mod φ(N)
```

Here, `d` is the private exponent and `e` is the public exponent.
