# name of your application
APPLICATION = sensors

# If no BOARD is found in the environment, use this default:
BOARD ?= unwd-range-l1-r3

USEMODULE += periph_gpio
USEMODULE += periph_i2c
USEMODULE += xtimer

USEMODULE += opt3001
USEMODULE += bme280_i2c

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
DEVELHELP ?= 1

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

include $(RIOTBASE)/Makefile.include
