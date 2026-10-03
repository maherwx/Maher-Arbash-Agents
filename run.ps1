param([string]$Scope=".\examples\scope.yaml",[string]$Rules=".\examples\rules.yaml")
python -m pip install -e .
maher-bounty run --scope $Scope --rules $Rules
