import panel as pn

# Initialize Panel extension
pn.extension()

# Use a direct image URL (replace with the correct one)
image_url = "https://iskconcongregation.com/wp-content/uploads/2019/08/60363159_2083365338628890_3005969175777640448_n-600x786.jpg"

# Display the image
pn.pane.Image(image_url).servable()
import re

from astropy import units as u
import numpy as np
import pandas as pd
from plotly import graph_objects as go
from plotly.callbacks import BoxSelector


from tardis.analysis import LastLineInteraction
from tardis.util.base import (
    species_tuple_to_string,
    species_string_to_tuple,
    is_notebook,
)

from tardis.visualization import plot_util as pu
from tardis.visualization.widgets.util import (
    create_table_widget,
    TableSummaryLabel,
)


import panel as pn
import pandas as pd
import numpy as np
from astropy import units as u
pn.extension()


from tardis import run_tardis
from tardis.io.atom_data import download_atom_data

# We download the atomic data needed to run the simulation
download_atom_data("kurucz_cd23_chianti_H_He")

sim = run_tardis("tardis_example.yml", virtual_packet_logging=True)
import panel as pn
import pandas as pd
import numpy as np
from astropy import units as u
import holoviews as hv
from bokeh.models import BoxSelectTool, CustomJS
from bokeh.plotting import figure
from bokeh.layouts import column

# Enable panel and holoviews extensions
pn.extension()
hv.extension('bokeh')

class LineInfoWidget_gsoc:
    FILTER_MODES = ("packet_out_nu", "packet_in_nu")
    FILTER_MODES_DESC = ("Emitted Wavelength", "Absorbed Wavelength")
    GROUP_MODES = ("both", "exc", "de-exc")
    GROUP_MODES_DESC = (
        "Both excitation line (absorption) and de-excitation line (emission)",
        "Only excitation line (absorption)",
        "Only de-excitation line (emission)",
    )
    COLORS = {"selection_area": "lightpink", "selection_border": "salmon"}

    def __init__(
        self,
        lines_data,
        line_interaction_analysis,
        spectrum_wavelength,
        spectrum_luminosity_density_lambda,
        virt_spectrum_wavelength,
        virt_spectrum_luminosity_density_lambda,
    ):
        self.lines_data = lines_data
        self.line_interaction_analysis = line_interaction_analysis
        self.spectrum_wavelength = spectrum_wavelength
        self.spectrum_luminosity_density_lambda = spectrum_luminosity_density_lambda
        self.virt_spectrum_wavelength = virt_spectrum_wavelength
        self.virt_spectrum_luminosity_density_lambda = virt_spectrum_luminosity_density_lambda

    @classmethod
    def from_simulation(cls, sim):
        spectrum_solver = sim.spectrum_solver
        return cls(
            lines_data=sim.plasma.lines.reset_index().set_index('line_id'),
            line_interaction_analysis={
                filter_mode: LastLineInteraction.from_simulation(sim, filter_mode)
                for filter_mode in cls.FILTER_MODES
            },
            spectrum_wavelength=spectrum_solver.spectrum_real_packets.wavelength,
            spectrum_luminosity_density_lambda=spectrum_solver.spectrum_real_packets.luminosity_density_lambda.to("erg/(s AA)"),
            virt_spectrum_wavelength=spectrum_solver.spectrum_virtual_packets.wavelength,
            virt_spectrum_luminosity_density_lambda=spectrum_solver.spectrum_virtual_packets.luminosity_density_lambda.to("erg/(s AA)")
        )

    def get_species_interactions(self, wavelength_range, filter_mode=FILTER_MODES[0]):
        print(f"get_species_interactions called with wavelength_range={wavelength_range}, filter_mode={filter_mode}")
        if wavelength_range:
            self.line_interaction_analysis[filter_mode].wavelength_start = (wavelength_range[0] * u.AA)
            self.line_interaction_analysis[filter_mode].wavelength_end = (wavelength_range[1] * u.AA)

            selected_species_group = self.line_interaction_analysis[filter_mode].last_line_in.groupby(["atomic_number", "ion_number"])

            if selected_species_group.groups:
                selected_species_symbols = [species_tuple_to_string(item) for item in selected_species_group.groups.keys()]
                fractional_species_interactions = selected_species_group.size() / self.line_interaction_analysis[filter_mode].last_line_in.shape[0]
                print(f"Selected species: {selected_species_symbols}, Fractions: {fractional_species_interactions}")
            else:
                selected_species_symbols = ['']
                fractional_species_interactions = pd.Series([""])
                print("No species found in the selected wavelength range.")
        else:
            selected_species_symbols = ['']
            fractional_species_interactions = pd.Series([''])
            print("Wavelength range is None, returning empty dataframe.")

        fractional_species_interactions.index = pd.Index(selected_species_symbols, name='Species')
        fractional_species_interactions.name = "Fraction of packet interacting"
        df = fractional_species_interactions.sort_values(ascending=False).to_frame()
        print(f"Returning species interactions dataframe:\n{df}")
        return df

    def get_last_line_counts(self, selected_species, filter_mode=FILTER_MODES[0], group_mode=GROUP_MODES[0]):
        print(f"get_last_line_counts called with species={selected_species}, filter_mode={filter_mode}, group_mode={group_mode}")
        if selected_species:
            selected_species_tuple = species_string_to_tuple(selected_species)
            try:
                current_last_lines_in = (
                    self.line_interaction_analysis[filter_mode].last_line_in.xs(
                        key=selected_species_tuple,
                        level=['atomic_number', 'ion_number'],
                        drop_level=False,
                    ).reset_index()
                )
                current_last_lines_out = self.line_interaction_analysis[filter_mode].last_line_out.xs(
                    key=selected_species_tuple,
                    level=['atomic_number', 'ion_number']
                ).reset_index()
                assert (current_last_lines_in.empty & current_last_lines_out.empty) == False
            except (KeyError, AssertionError):
                allowed_species = [
                    species_tuple_to_string(species) for species in self.line_interaction_analysis[filter_mode].last_line_in.groupby(['atomic_number', 'ion_number']).groups.keys()
                ]
                print(f"Invalid species: {selected_species}. Allowed species: {allowed_species}")
                raise ValueError(
                    "Invalid value of selected_species, it must be one present "
                    "within the currently selected wavelength range in your "
                    f"LineInfoWidget instance, which are {allowed_species}"
                )
            last_line_interaction_string = []
            interacting_packets_count = []
            if group_mode == 'both':
                if len(current_last_lines_in) != len(current_last_lines_out):
                    raise ValueError(
                        f"Mismatch in number of rows: current_last_lines_in has {len(current_last_lines_in)} rows, "
                        f"but current_last_lines_out has {len(current_last_lines_out)} rows."
                    )
                current_last_lines_in["line_id_out"] = current_last_lines_out.line_id
                grouped_line_interactions = current_last_lines_in.groupby(['line_id', 'line_id_out'])
                for (line_id, count) in grouped_line_interactions.size().items():
                    current_line_in = self.lines_data.loc[line_id[0]]
                    current_line_out = self.lines_data.loc[line_id[1]]
                    last_line_interaction_string.append(
                        f"exc. {int(current_line_in.level_number_lower):02d}-"
                        f"{int(current_line_in.level_number_upper):02d} "
                        f"({current_line_in.wavelength:.2f} A) "
                        f"de-exc. {int(current_line_out.level_number_upper):02d}-"
                        f"{int(current_line_out.level_number_lower):02d} "
                        f"({current_line_out.wavelength:.2f} A)"
                    )
                    interacting_packets_count.append(count)
            elif group_mode == 'exc':
                grouped_line_interactions = current_last_lines_in.groupby('line_id')
                for (line_id, count) in grouped_line_interactions.size().items():
                    current_line_in = self.lines_data.loc[line_id]
                    last_line_interaction_string.append(
                        f"exc. {int(current_line_in.level_number_lower):02d}-"
                        f"{int(current_line_in.level_number_upper):02d} "
                        f"({current_line_in.wavelength:.2f} A)"
                    )
                    interacting_packets_count.append(count)
            elif group_mode == 'de-exc':
                grouped_line_interactions = current_last_lines_out.groupby("line_id")
                for (line_id, count) in grouped_line_interactions.size().items():
                    current_line_out = self.lines_data.loc[line_id]
                    last_line_interaction_string.append(
                        f"de-exc. {int(current_line_out.level_number_upper):02d}-"
                        f"{int(current_line_out.level_number_lower):02d} "
                        f"({current_line_out.wavelength:.2f} A)"
                    )
                    interacting_packets_count.append(count)
            else:
                raise ValueError(f"Invalid value passed to group mode argument. Allowed values are {self.GROUP_MODES}")
        else:
            interacting_packets_count = ['']
            last_line_interaction_string = ['']

        last_line_counts = pd.Series(interacting_packets_count)
        last_line_counts.name = "No. of packets"
        last_line_counts.index = pd.Index(last_line_interaction_string, name="Last Line Interaction")
        df = last_line_counts.sort_values(ascending=False).to_frame()
        print(f"Returning last line counts dataframe:\n{df}")
        return df

    @staticmethod
    def get_middle_half_edges(arr):
        arr = np.sort(arr)
        return [(arr[-1] - arr[0]) / 4 + arr[0], (arr[-1] - arr[0]) * 3 / 4 + arr[0]]

    def _update_species_interactions(self, wavelength_range, filter_mode):
        print(f"Updating species interactions with wavelength_range={wavelength_range}, filter_mode={filter_mode}")
        self.species_interactions_table.value = self.get_species_interactions(wavelength_range, filter_mode)
        print(f"Updated species interactions table:\n{self.species_interactions_table.value}")
        if not self.species_interactions_table.value.empty and self.species_interactions_table.value.index[0]:
            self.species_interactions_table.selection = [0]
        else:
            self.species_interactions_table.selection = []

    def _update_last_line_counts(self, species, filter_mode, group_mode):
        print(f"Updating last line counts for species={species}, filter_mode={filter_mode}, group_mode={group_mode}")
        df = self.get_last_line_counts(species, filter_mode, group_mode)
        self.last_line_counts_table.value = df
        total = df["No. of packets"].sum() if not df.empty and df["No. of packets"].notna().any() else 0
        self.total_packets_label.value = str(int(total)) if total else "0"
        print(f"Updated last line counts table:\n{self.last_line_counts_table.value}, Total packets: {self.total_packets_label.value}")

class LineInfoWidgetVisualizer(LineInfoWidget_gsoc):
    def __init__(self, lines_data, line_interaction_analysis, spectrum_wavelength, spectrum_luminosity_density_lambda, virt_spectrum_wavelength, virt_spectrum_luminosity_density_lambda):
        super().__init__(lines_data, line_interaction_analysis, spectrum_wavelength, spectrum_luminosity_density_lambda, virt_spectrum_wavelength, virt_spectrum_luminosity_density_lambda)
        self._init_ui()

    def _init_ui(self):
        # Toggle buttons for filter mode (Emitted/Absorbed Wavelength)
        self.filter_mode_toggle = pn.widgets.ToggleGroup(
            name="Filter selected wavelength range by:",
            options=dict(zip(self.FILTER_MODES_DESC, self.FILTER_MODES)),
            value=self.FILTER_MODES[0],
            button_type="primary",
            behavior="radio"
        )

        # Dropdown for group mode (Both, Excitation, De-excitation)
        self.group_mode_dropdown = pn.widgets.Select(
            name="Group packets count by:",
            options=dict(zip(self.GROUP_MODES_DESC, self.GROUP_MODES)),
            value=self.GROUP_MODES[0]
        )

        # Reset button for wavelength range
        self.reset_button = pn.widgets.Button(
            name="Reset Wavelength Range",
            button_type="default"
        )
        self.reset_button.on_click(self._reset_wavelength_range)

        # Table for species interactions
        self.species_interactions_table = pn.widgets.DataFrame(
            value=pd.DataFrame({"Species": [""], "Fraction of packet interacting": [""]}),
            name="Species Interactions",
            auto_edit=False,
            selection=[0]
        )

        # Table for last line counts
        self.last_line_counts_table = pn.widgets.DataFrame(
            value=pd.DataFrame({"Last Line Interaction": [""], "No. of packets": [""]}),
            name="Last Line Counts",
            auto_edit=False
        )

        # Label for total packets
        self.total_packets_label = pn.widgets.StaticText(
            name="Total Packets:", value="0"
        )

        # Set up event watchers
        self.filter_mode_toggle.param.watch(self._on_filter_change_mode, "value")
        self.group_mode_dropdown.param.watch(self._group_mode_change, "value")
        self.species_interactions_table.param.watch(self._on_species_selection_change, "selection")
        self.wavelength_range = None

        # Create the spectrum plot
        self._create_spectrum_plot()

    def _create_spectrum_plot(self):
        # Extract wavelength and luminosity data
        real_wavelength = self.spectrum_wavelength.value  # in Angstrom
        real_luminosity = self.spectrum_luminosity_density_lambda.value  # in erg/s/AA
        virt_wavelength = self.virt_spectrum_wavelength.value
        virt_luminosity = self.virt_spectrum_luminosity_density_lambda.value

        # Debug: Check the data
        print(f"Real wavelength shape: {real_wavelength.shape}, min: {real_wavelength.min() if real_wavelength.size > 0 else 'N/A'}, max: {real_wavelength.max() if real_wavelength.size > 0 else 'N/A'}")
        print(f"Real luminosity shape: {real_luminosity.shape}, min: {real_luminosity.min() if real_luminosity.size > 0 else 'N/A'}, max: {real_luminosity.max() if real_luminosity.size > 0 else 'N/A'}")
        print(f"Virtual wavelength shape: {virt_wavelength.shape}, min: {virt_wavelength.min() if virt_wavelength.size > 0 else 'N/A'}, max: {virt_wavelength.max() if virt_wavelength.size > 0 else 'N/A'}")
        print(f"Virtual luminosity shape: {virt_luminosity.shape}, min: {virt_luminosity.min() if virt_luminosity.size > 0 else 'N/A'}, max: {virt_luminosity.max() if virt_luminosity.size > 0 else 'N/A'}")

        # Check if data is valid for plotting
        if (real_wavelength.size == 0 or real_luminosity.size == 0 or
            virt_wavelength.size == 0 or virt_luminosity.size == 0 or
            np.any(np.isnan(real_wavelength)) or np.any(np.isnan(real_luminosity)) or
            np.any(np.isnan(virt_wavelength)) or np.any(np.isnan(virt_luminosity))):
            print("Invalid or empty data for spectrum plot. Displaying placeholder.")
            self.spectrum_plot = pn.pane.Markdown("### No spectrum data available to plot.")
            return

        # Create the main plot
        p = figure(
            title="Spectrum",
            x_axis_label="Wavelength [Å]",
            y_axis_label="Luminosity [erg/s/Å]",
            height=400,  # Increased height since there's no secondary plot
            width=800,
            tools="pan,box_zoom,reset,save,wheel_zoom,box_select",  # Added box_select tool
            title_location="above",
            toolbar_location="right"
        )

        # Plot real and virtual spectra with thicker lines
        real_line = p.line(real_wavelength, real_luminosity, legend_label="Real packets", color="blue", line_width=2)
        virt_line = p.line(virt_wavelength, virt_luminosity, legend_label="Virtual packets", color="red", line_width=2)

        # Style the plot
        p.title.text_font_size = "14pt"
        p.xaxis.axis_label_text_font_size = "12pt"
        p.yaxis.axis_label_text_font_size = "12pt"
        p.legend.location = "top_right"
        p.legend.label_text_font_size = "10pt"

        # Add BoxSelectTool and configure its callback
        box_select = BoxSelectTool()
        p.add_tools(box_select)
        p.select(type=BoxSelectTool).select_every_mousemove = False  # Only trigger on selection completion

        # CustomJS callback to update x_range based on box selection
        callback = CustomJS(args=dict(x_range=p.x_range), code="""
            const geometry = cb_obj.geometry;
            if (geometry && geometry.x0 != null && geometry.x1 != null) {
                x_range.start = geometry.x0;
                x_range.end = geometry.x1;
                x_range.change.emit();
            }
        """)
        real_line.data_source.js_on_change('selected', callback)
        virt_line.data_source.js_on_change('selected', callback)

        # Combine the plot into a pane
        self.spectrum_plot = pn.pane.Bokeh(p, sizing_mode="stretch_width", min_height=400)

        # Watch for changes in the x_range to update wavelength_range
        p.x_range.on_change('start', self._on_wavelength_range_change)
        p.x_range.on_change('end', self._on_wavelength_range_change)

        # Set initial wavelength range to the middle half and store it
        self.initial_wavelength_range = self.get_middle_half_edges(real_wavelength)
        p.x_range.start = self.initial_wavelength_range[0]
        p.x_range.end = self.initial_wavelength_range[1]
        self.wavelength_range = self.initial_wavelength_range
        print(f"Initial wavelength range set to: {self.wavelength_range}")

    def _reset_wavelength_range(self, event):
        # Reset the wavelength range to the initial range
        print("Resetting wavelength range to initial range.")
        self.spectrum_plot.object.x_range.start = self.initial_wavelength_range[0]
        self.spectrum_plot.object.x_range.end = self.initial_wavelength_range[1]
        self.wavelength_range = self.initial_wavelength_range
        self._update_species_interactions(self.wavelength_range, self.filter_mode_toggle.value)

    def _on_wavelength_range_change(self, attr, old, new):
        # Update wavelength range when the user adjusts the range via box selection
        self.wavelength_range = [self.spectrum_plot.object.x_range.start,
                                self.spectrum_plot.object.x_range.end]
        print(f"Wavelength range updated to: {self.wavelength_range}")
        self._update_species_interactions(self.wavelength_range, self.filter_mode_toggle.value)

    def _on_filter_change_mode(self, event):
        print(f"Filter mode changed to: {event.new}")
        self._update_species_interactions(self.wavelength_range, event.new)

    def _group_mode_change(self, event):
        print(f"Group mode changed to: {event.new}")
        selected_rows = self.species_interactions_table.selection
        if selected_rows:
            species = self.species_interactions_table.value.index[selected_rows[0]]
            self._update_last_line_counts(species, self.filter_mode_toggle.value, event.new)

    def _on_species_selection_change(self, event):
        selected_rows = event.new
        print(f"Species selection changed to: {selected_rows}")
        if selected_rows:
            species = self.species_interactions_table.value.index[selected_rows[0]]
            self._update_last_line_counts(species, self.filter_mode_toggle.value, self.group_mode_dropdown.value)
        else:
            self.last_line_counts_table.value = pd.DataFrame({"Last Line Interaction": [""], "No. of packets": [""]})
            self.total_packets_label.value = "0"

    def create_lower_half(self):
        controls = pn.Row(
            self.filter_mode_toggle,
            self.group_mode_dropdown,
            self.reset_button,
            align="center"
        )
        tables = pn.Row(
            pn.Column(
                self.species_interactions_table,
                width=400
            ),
            pn.Column(
                self.last_line_counts_table,
                self.total_packets_label,
                width=600
            )
        )
        return pn.Column(controls, tables)

    def create_full_ui(self):
        return pn.Column(
            self.spectrum_plot,
            self.create_lower_half(),
            sizing_mode="stretch_width"
        )


widget_box_select_update = LineInfoWidgetVisualizer.from_simulation(sim)
full_ui_widget = widget_box_select_update.create_full_ui()
full_ui_widget.show()

