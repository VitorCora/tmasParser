# How to run it

pip install -r requirements.txt
python tmasparser.py -tmas tmas_output.json

python pipelinefail.py --input tmasParser_output.json --critical true --critical-unmitigated true --high true --high-unmitigated true --medium true --medium-unmitigated true --low true --low-unmitigated true --malware true --secrets true

