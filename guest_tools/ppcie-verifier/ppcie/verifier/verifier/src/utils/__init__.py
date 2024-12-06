#    Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
import logging


class SimpleMessageHandler(logging.StreamHandler):
    def emit(self, record):
        try:
            msg = self.format(record)
            stream = self.stream
            formatted_msg = self.center_message(msg, width=50)  # Adjust width as needed
            stream.write(f"{formatted_msg}\n")
            self.flush()
        except Exception:
            self.handleError(record)

    def center_message(self, msg, width):
        """
        This method constructs a box around a centered message.

        Parameters:
        msg (str): The message to be centered.
        width (int): The total width of the box.

        Returns:
        str: The box with the centered message.

        The box is constructed using asterisks (*) and has a width equal to the input width.
        The message is centered within the box, and the box is padded with spaces around the message.
        If the message is longer than the specified width, it is truncated to fit within the box.
        """
        # Define the total width of the box
        total_width = width
        # Calculate padding
        padding = (
            total_width - len(msg) - 2
        ) // 2  # Subtract 2 for the spaces around the message
        if padding < 0:
            padding = 0
        # Construct the centered message
        centered_msg = f"*{' ' * padding}{msg}{' ' * padding}*"
        if len(centered_msg) < total_width:
            centered_msg = centered_msg[:-1] + "*"
        # Construct the full box with @ symbols
        box_top_bottom = "*" * total_width
        return f"{box_top_bottom}\n{centered_msg}\n{box_top_bottom}"
