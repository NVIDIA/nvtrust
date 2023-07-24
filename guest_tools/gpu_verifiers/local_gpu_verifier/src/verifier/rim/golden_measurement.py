#
# SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
from verifier.config import info_log

class GoldenMeasurement:
    """ A class to represent the individual golden measurement values from the RIM files.
    """

    def __init__(self, component, values, name, index, size, alternatives, active):
        """ Constructor method to create the object for the individual golden measurement.

        Args:
            component (str): the component name for which the golden
                             measurement belongs "driver" or "vbios".
            values (list): the list of valid/alternative golden measurement.
            name (str): the name of the measurement.
            index (int): the index of the measurement.
            size (int): the size of the measurement value in number of bytes.
            alternatives (int): number of valid/alternative measurements.
            active (bool): True if the measurement is to be used for
                           comparision with the runtime measurement else False.
        """
        self.set_component(component)
        self.set_value(values)
        self.set_name(name)
        self.set_index(index)
        self.set_size(size)
        self.set_number_of_alternatives(alternatives)
        self.set_active(active)
    
    def get_component(self):
        """ Fetches the component name for which the measurement belongs,
        either "driver" or "vbios".

        Returns:
            [str]: the component name, one of the value "driver"/"vbios".
        """
        return self.component
    
    def set_component(self, component):
        """ Sets the component name to the golden measurement. It can be either
        "driver" or "vbios".

        Args:
            component (str): component name. It can be either "driver" for 
            driver measurement or "vbios" for vbios measurement.
        """
        self.component = component
    
    def get_value_at_index(self, index):
        """ Fetches the golden measurement value at the given index among the
        alternative values of the golden measurement at a particular
        measurement index. 

        Args:
            index (int): the position of the value in the list of alternative
            measurement values.

        Returns:
            [str]: the measurement value.
        """
        assert type(index) is int
        return self.values[index]

    def set_value(self, values):
        """ Sets the list of measurement values to the GoldenMeasurement class
        object.

        Args:
            values (list): the list of valid golden measurement at an index.
        """
        assert type(values) is list
        self.values = values
    
    def get_name(self):
        """ Fetches the name of the golden measurement.

        Returns:
            [str]: the name of the golden measurement.
        """
        return self.name
    
    def set_name(self, name):
        """ Sets the name of measurement values to the GoldenMeasurement class
        object.

        Args:
            name (str): the name of the golden measurement.
        """
        self.name = name
    
    def get_index(self):
        """ Fetches the index of the golden measurement.

        Returns:
            [int]: the index of the golden measurement.
        """
        return self.index
    
    def set_index(self, index):
        """ Sets the index of the golden measurement.

        Args:
            index (int): the index of the golden measurement.
        """
        self.index = index
    
    def get_size(self):
        """ Fetches the size of the golden measurement value in number of bytes.

        Returns:
            [int]: the size of the measurement.
        """
        return self.size
    
    def set_size(self, size):
        """ Sets the size of the golden measurement value in number of bytes.

        Args:
            size (int): the size of the measurement.
        """
        self.size = size
    
    def get_number_of_alternatives(self):
        """ Fetches the number of valid alternative values for the golden
        measurement.

        Returns:
            [int]: the number of valid values.
        """
        return self.alternatives
    
    def set_number_of_alternatives(self, value):
        """ Sets the number of valid alternative values for the golden
        measurement.

        Args:
            value (int): the numner of valid values.
        """
        self.alternatives = value
    
    def is_active(self):
        """ Checks if the given golden measurement needs to be compared with
        the corresponding run time measurement.

        Returns:
            [bool]: True if being used for comparison with runtime 
                    measurement otherwise returns False.
        """
        return self.active
    
    def set_active(self, active):
        """ Sets wether the given golden measurement needs to be compared with
        the corresponding run time measurement or not.

        Args:
            active (bool): True if being used for comparison with runtime 
                    measurement otherwise returns False.
        """
        self.active = active
    
    def print_obj(self, logger):
        """ This method prints the various fields of the GoldenMeasurement
        class object representing the individual golden measurement.

        Args:
            logger (logging.Logger): the logger object.
        """
        logger.info('-----------------------------------')
        logger.info(f"\tcomponent : {self.component}")
        logger.info(f"\tvalue     : {self.value}")
        logger.info(f"\tname      : {self.name}")
        logger.info(f"\tindex     : {self.index}")
        logger.info(f"\tsize      : {self.size}")
        logger.info(f"\tnullable  : {self.nullable}")
        logger.info(f"\tactive    : {self.active}")
