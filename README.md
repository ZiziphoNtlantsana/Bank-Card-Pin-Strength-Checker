# Bank Card PIN Strength Checker

A tool I built in Python that checks whether a 4-digit bank card PIN is easy to guess.

## What it does

Banks assume a 4-digit PIN gives 10,000 possible combinations — but in reality, people reuse the same weak patterns over and over (think `1234`, `0000`, or your birth year). This tool catches those patterns and tells you whether a PIN is weak or strong, and why.

It checks for:
- PINs that are too short, too long, or not numeric
- Sequences like `1234` or `4321`
- Repeated digits like `1111`
- PINs that show up on real published lists of the most commonly used PINs

## Try it

```bash
python pin_strength_checker.py 1234
```

## Why I built this

This started as a small project to practise thinking like an attacker. The same logic that shows up in real password-cracking tools, applied to something everyday people actually use. It's also fully tested, with 8 automated checks confirming the logic works correctly.

## About me

Zizipho Ntlantsana — network engineer moving into cybersecurity.
[GitHub](https://github.com/ZiziphoNtlantsana)
