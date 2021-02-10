use std::collections::HashMap;
use std::cmp::Ordering;
use anyhow::Result;

enum Value {
    S(String),
    U(u64),
}

#[derive(Clone)]
struct Column {
    name: String,
    width: usize,
}

pub struct Row {
    data: HashMap<String, Value>,
}

impl Row {
    pub fn new() -> Row {
        Row {
            data: HashMap::new()
        }
    }

    pub fn add_str<S1, S2>(&mut self, name: S1, value: S2)
    where
        S1: AsRef<str>,
        S2: AsRef<str>,
    {
        let name = name.as_ref().to_string();
        let value = value.as_ref().to_string();

        self.data.insert(name, Value::S(value));
    }

    pub fn add_u64<S1>(&mut self, name: S1, value: u64)
    where
        S1: AsRef<str>
    {
        let name = name.as_ref().to_string();

        self.data.insert(name, Value::U(value));
    }
}

pub struct Table {
    header: bool,
    outputs: Vec<Column>,
    output_filter: Option<Vec<String>>,
    sort_order: Option<Vec<SortOrder>>,

    data: Vec<Row>,
}

impl Table {
    pub fn add_row(&mut self, row: Row) {
        self.data.push(row);
    }

    pub fn output(&mut self) -> Result<String> {
        if let Some(order) = &self.sort_order {
            let order = order.clone();

            self.data.sort_by(|a, b| {
                /*
                 * Try each of the columns in the provided sort order:
                 */
                for so in order.iter() {
                    let aval = a.data.get(&so.column).expect("sort value");
                    let bval = b.data.get(&so.column).expect("sort value");

                    let cmp = match (aval, bval) {
                        (Value::S(a), Value::S(b)) => if so.ascending {
                            a.cmp(b)
                        } else {
                            b.cmp(a)
                        }
                        (Value::U(a), Value::U(b)) => if so.ascending {
                            a.cmp(b)
                        } else {
                            b.cmp(a)
                        }
                        _ => panic!("Datums in a column must be same shape"),
                    };

                    match cmp {
                        Ordering::Equal => (),
                        Ordering::Less | Ordering::Greater => return cmp,
                    }
                }

                Ordering::Equal
            });
        }

        let filter: Vec<Column> = if let Some(filter) = &self.output_filter {
            filter.iter().map(|n| {
                self.outputs.iter().find(|c| &c.name == n).unwrap().clone()
            }).collect()
        } else {
            self.outputs.clone()
        };

        let mut out = String::new();

        if self.header {
            let mut line = String::new();

            for col in filter.iter() {
                line += &format!("{:width$} ", col.name.to_uppercase(),
                    width = col.width);
            }

            out += line.trim_end();
            out += "\n";
        }

        for row in self.data.iter() {
            let mut line = String::new();

            for col in filter.iter() {
                let val = row.data.get(&col.name).expect("output value");

                let data = match val {
                    Value::S(s) => format!("{}", s),
                    Value::U(n) => format!("{}", n),
                };

                line += &format!("{:width$} ", data, width = col.width);
            }

            out += line.trim_end();
            out += "\n";
        }

        Ok(out)
    }
}

#[derive(Clone)]
struct SortOrder {
    column: String,
    ascending: bool,
}

pub struct TableBuilder {
    header: bool,
    outputs: Vec<Column>,
    output_filter: Option<Vec<String>>,
    sort_order: Option<Vec<SortOrder>>,
}

impl TableBuilder {
    pub fn new() -> TableBuilder {
        TableBuilder {
            header: true,
            outputs: Vec::new(),
            output_filter: None,
            sort_order: None,
        }
    }

    /**
     * Parse a comma-separated list of column names to determine which columns
     * to include in the display, and in what order.  This routine is meant to
     * accept the value of a "-o" argument; e.g., "-o name,size,colour".
     */
    pub fn output_from_list(&mut self, list: Option<&str>)
        -> &mut TableBuilder
    {
        if let Some(list) = list {
            let mut x = Vec::new();
            for col in list.split(',') {
                x.push(col.trim().to_lowercase().to_string());
            }
            self.output_filter = Some(x);
        }
        self
    }

    /**
     * Parse a comma-separated list of column names to determine the sort order
     * for the table.  This routine is meant to accept the value of a "-s"
     * argument; e.g., "-s id,name".
     */
    pub fn sort_from_list_asc(&mut self, list: Option<&str>)
        -> &mut TableBuilder
    {
        if let Some(list) = list {
            let mut x = Vec::new();
            for col in list.split(',') {
                x.push(SortOrder {
                    column: col.trim().to_lowercase().to_string(),
                    ascending: true,
                });
            }
            self.sort_order = Some(x);
        }
        self
    }

    /**
     * Parse a comma-separated list of column names to determine the sort order
     * for the table.  This routine is meant to accept the value of a "-S"
     * argument; e.g., "-S id,name".
     */
    pub fn sort_from_list_desc(&mut self, list: Option<&str>)
        -> &mut TableBuilder
    {
        if let Some(list) = list {
            let mut x = Vec::new();
            for col in list.split(',') {
                x.push(SortOrder {
                    column: col.trim().to_lowercase().to_string(),
                    ascending: false,
                });
            }
            self.sort_order = Some(x);
        }
        self
    }

    /**
     * Add a possible column, with its default display width, to the Table
     * definition.  If there is no output filter, then the order of add_column()
     * calls will determine the displayed order of columns.
     */
    pub fn add_column(&mut self, name: &str, width: usize)
        -> &mut TableBuilder
    {
        self.outputs.push(Column {
            name: name.to_string(),
            width,
        });
        self
    }

    /**
     * Decide whether to render a header at the top of the table or not.
     */
    #[allow(dead_code)]
    pub fn show_header(&mut self, show: bool)
        -> &mut TableBuilder
    {
        self.header = show;
        self
    }

    pub fn disable_header(&mut self, disable: bool)
        -> &mut TableBuilder
    {
        if disable {
            self.header = false;
        }
        self
    }

    /**
     * Construct the final Table object, to which rows may be appended for
     * eventual display.
     */
    pub fn build(&mut self) -> Table {
        Table {
            header: self.header,
            outputs: self.outputs.clone(),
            output_filter: self.output_filter.clone(),
            sort_order: self.sort_order.clone(),
            data: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Table, TableBuilder, Row};

    fn longer_row(id: u64, name: &str, colour: &str, rating: u64) -> Row {
        let mut row = Row::new();
        row.add_u64("id", id);
        row.add_str("name", name);
        row.add_str("colour", colour);
        row.add_u64("rating", rating);
        row
    }

    fn longer_data(table: &mut Table) {
        table.add_row(longer_row(2, "chocolate", "brown", 5));
        table.add_row(longer_row(1, "vanilla", "white", 4));
        table.add_row(longer_row(3, "strawberry", "pink", 8));
        table.add_row(longer_row(4, "pistachio", "green", 4));
        table.add_row(longer_row(5, "lemon", "yellow", 6));
    }

    fn basic_row(id: u64, name: &str) -> Row {
        let mut row = Row::new();
        row.add_u64("id", id);
        row.add_str("name", name);
        row
    }

    fn basic_data(table: &mut Table) {
        table.add_row(basic_row(1, "john"));
        table.add_row(basic_row(4, "bruce"));
        table.add_row(basic_row(2, "albert"));
        table.add_row(basic_row(3, "zeta"));
    }

    fn basic_data_dups(table: &mut Table) {
        table.add_row(basic_row(1, "john"));
        table.add_row(basic_row(4, "bruce"));
        table.add_row(basic_row(2, "albert"));
        table.add_row(basic_row(2, "demonstration"));
        table.add_row(basic_row(3, "zeta"));
        table.add_row(basic_row(5, "almond"));
        table.add_row(basic_row(1, "almond"));
        table.add_row(basic_row(2, "carrot"));
    }

    #[test]
    fn basic_nosort() {
        let mut t = TableBuilder::new()
            .show_header(true)
            .add_column("id", 8)
            .add_column("name", 24)
            .build();

        basic_data(&mut t);

        assert_eq!(
            t.output().expect("output"),
            "ID       NAME\n\
            1        john\n\
            4        bruce\n\
            2        albert\n\
            3        zeta\n\
            ");
    }

    #[test]
    fn basic_sort_id() {
        let mut t = TableBuilder::new()
            .show_header(true)
            .add_column("id", 8)
            .add_column("name", 24)
            .sort_from_list_asc(Some("id"))
            .build();

        basic_data(&mut t);

        assert_eq!(
            t.output().expect("output"),
            "ID       NAME\n\
            1        john\n\
            2        albert\n\
            3        zeta\n\
            4        bruce\n\
            ");
    }

    #[test]
    fn basic_sort_name() {
        let mut t = TableBuilder::new()
            .show_header(true)
            .add_column("id", 8)
            .add_column("name", 24)
            .sort_from_list_asc(Some("name"))
            .build();

        basic_data(&mut t);

        assert_eq!(
            t.output().expect("output"),
            "ID       NAME\n\
            2        albert\n\
            4        bruce\n\
            1        john\n\
            3        zeta\n\
            ");
    }

    #[test]
    fn basic_sort_idname() {
        let mut t = TableBuilder::new()
            .show_header(true)
            .add_column("id", 8)
            .add_column("name", 24)
            .sort_from_list_asc(Some("id,name"))
            .build();

        basic_data_dups(&mut t);

        assert_eq!(
            t.output().expect("output"),
            "ID       NAME\n\
            1        almond\n\
            1        john\n\
            2        albert\n\
            2        carrot\n\
            2        demonstration\n\
            3        zeta\n\
            4        bruce\n\
            5        almond\n\
            ");
    }

    #[test]
    fn basic_sort_nameid() {
        let mut t = TableBuilder::new()
            .show_header(true)
            .add_column("id", 8)
            .add_column("name", 24)
            .sort_from_list_asc(Some("name,id"))
            .build();

        basic_data_dups(&mut t);

        assert_eq!(
            t.output().expect("output"),
            "ID       NAME\n\
            2        albert\n\
            1        almond\n\
            5        almond\n\
            4        bruce\n\
            2        carrot\n\
            2        demonstration\n\
            1        john\n\
            3        zeta\n\
            ");
    }

    #[test]
    fn longer_name_rating() {
        let mut t = TableBuilder::new()
            .show_header(true)
            .add_column("id", 8)
            .add_column("name", 16)
            .add_column("colour", 16)
            .add_column("rating", 8)
            .output_from_list(Some("rating,name"))
            .build();

        longer_data(&mut t);

        assert_eq!(
            t.output().expect("output"),
            "RATING   NAME\n\
            5        chocolate\n\
            4        vanilla\n\
            8        strawberry\n\
            4        pistachio\n\
            6        lemon\n\
            ");
    }

    #[test]
    fn longer_best_with_colour() {
        let mut t = TableBuilder::new()
            .show_header(true)
            .add_column("id", 8)
            .add_column("name", 16)
            .add_column("colour", 16)
            .add_column("rating", 8)
            .sort_from_list_desc(Some("rating"))
            .output_from_list(Some("rating,name,colour"))
            .build();

        longer_data(&mut t);

        assert_eq!(
            t.output().expect("output"),
            "RATING   NAME             COLOUR\n\
            8        strawberry       pink\n\
            6        lemon            yellow\n\
            5        chocolate        brown\n\
            4        vanilla          white\n\
            4        pistachio        green\n\
            ");
    }

    #[test]
    fn longer_worst_with_colour() {
        let mut t = TableBuilder::new()
            .show_header(true)
            .add_column("id", 8)
            .add_column("name", 16)
            .add_column("colour", 16)
            .add_column("rating", 8)
            .sort_from_list_asc(Some("rating"))
            .output_from_list(Some("rating,name,colour"))
            .build();

        longer_data(&mut t);

        assert_eq!(
            t.output().expect("output"),
            "RATING   NAME             COLOUR\n\
            4        vanilla          white\n\
            4        pistachio        green\n\
            5        chocolate        brown\n\
            6        lemon            yellow\n\
            8        strawberry       pink\n\
            ");
    }
}
