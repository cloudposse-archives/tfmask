clean:
	rm -rf .terraform

test: clean
	terraform init
	terraform plan | ../release/tfmask
	terraform apply -auto-approve | ../release/tfmask
	terraform taint random_string.some_password
	terraform taint random_id.some_id
	terraform plan  | ../release/tfmask
	terraform apply -auto-approve | ../release/tfmask
