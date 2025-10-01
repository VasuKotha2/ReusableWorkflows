if ! command -v snyk &> /dev/null
then
  if [[ "$OSTYPE" == msys* ]]; then
    curl -L https://github.com/snyk/cli/releases/latest/download/snyk-win.exe -o ./snyk.exe
  else
    curl -OL https://github.com/snyk/cli-releases/latest/download/snyk-linux
    sudo mv snyk-linux ./snyk
    sudo chmod +x ./snyk
  fi
fi

./snyk --version
./snyk config set disableSuggestions=true
./snyk auth --auth-type=token $SCA_TOKEN

