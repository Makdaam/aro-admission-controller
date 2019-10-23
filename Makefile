GITCOMMIT=$(shell git describe --tags HEAD)$(shell [[ $$(git status --porcelain) = "" ]] || echo -dirty)
ADC_IMAGE ?= quay.io/makdaam/aro-admission-controller:$(GITCOMMIT)

.PHONY: adc adc-image adc-push

adc:
	go build github.com/openshift/aro-admission-controller/cmd/admissioncontroller

adc-image: adc
	./hack/image-build.sh Dockerfile $(ADC_IMAGE)

adc-push: adc-image
	docker push $(ADC_IMAGE)

